/*
 * Copyright (c) 2019-2022 GeyserMC. http://geysermc.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author GeyserMC
 * @link https://github.com/GeyserMC/Geyser
 */

package org.geysermc.geyser.util;

import net.raphimc.minecraftauth.msa.model.MsaDeviceCode;
import org.cloudburstmc.protocol.bedrock.data.auth.AuthPayload;
import org.cloudburstmc.protocol.bedrock.data.auth.AuthType;
import org.cloudburstmc.protocol.bedrock.data.auth.CertificateChainPayload;
import org.cloudburstmc.protocol.bedrock.data.auth.TokenPayload;
import org.cloudburstmc.protocol.bedrock.packet.LoginPacket;
import org.cloudburstmc.protocol.bedrock.packet.ServerToClientHandshakePacket;
import org.cloudburstmc.protocol.bedrock.util.ChainValidationResult;
import org.cloudburstmc.protocol.bedrock.util.ChainValidationResult.IdentityData;
import org.cloudburstmc.protocol.bedrock.util.EncryptionUtils;
import org.geysermc.cumulus.form.ModalForm;
import org.geysermc.cumulus.form.SimpleForm;
import org.geysermc.cumulus.response.SimpleFormResponse;
import org.geysermc.cumulus.response.result.FormResponseResult;
import org.geysermc.cumulus.response.result.ValidFormResponseResult;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.network.bedrock.CodecProcessor;
import org.cloudburstmc.netty.util.nethernet.TransportIdentityBinding;
import org.geysermc.geyser.network.bedrock.nethernet.NetherNetPeer;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.session.auth.AuthData;
import org.geysermc.geyser.session.auth.BedrockClientData;
import org.geysermc.geyser.text.ChatColor;
import org.geysermc.geyser.text.GeyserLocale;

import javax.crypto.SecretKey;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.function.BiConsumer;

public class LoginEncryptionUtils {
    private static boolean HAS_SENT_ENCRYPTION_MESSAGE = false;

    public static void encryptPlayerConnection(GeyserSession session, LoginPacket loginPacket) {
        encryptConnectionWithCert(session, loginPacket.getAuthPayload(), loginPacket.getClientJwt());
    }

    private static void encryptConnectionWithCert(GeyserSession session, AuthPayload authPayload, String jwt) {
        try {
            GeyserImpl geyser = session.getGeyser();

            // Regardless of auth type, we don't support guest type accounts used for splitscreen
            if (authPayload.getAuthType() == AuthType.GUEST) {
                session.disconnect(GeyserLocale.getLocaleStringLog("geyser.network.remote.invalid_xbox_account"));
                return;
            }

            ChainValidationResult result = EncryptionUtils.validatePayload(authPayload);

            geyser.getLogger().debug("Is player data signed? %s", result.signed());
            if (!result.signed() && session.getGeyser().config().advanced().bedrock().validateBedrockLogin()) {
                session.disconnect(GeyserLocale.getLocaleStringLog("geyser.network.remote.invalid_xbox_account"));
                return;
            }

            // Should always be present, but hey, why not make it safe :D
            Long rawIssuedAt = (Long) result.rawIdentityClaims().get("iat");
            long issuedAt = rawIssuedAt != null ? rawIssuedAt : -1;

            if (authPayload instanceof TokenPayload tokenPayload) {
                session.setToken(tokenPayload.getToken());
            } else if (authPayload instanceof CertificateChainPayload certificateChainPayload) {
                session.setCertChainData(certificateChainPayload.getChain());
            } else {
                GeyserImpl.getInstance().getLogger().warning("Unknown auth payload! Skin uploading will not work");
            }

            PublicKey identityPublicKey = result.identityClaims().parsedIdentityPublicKey();

            byte[] clientDataPayload = EncryptionUtils.verifyClientData(jwt, identityPublicKey);
            if (clientDataPayload == null) {
                throw new IllegalStateException("Client data isn't signed by the given chain data");
            }

            BedrockClientData data = JsonUtils.fromJson(clientDataPayload, BedrockClientData.class);
            data.setOriginalString(jwt);
            session.setClientData(data);

            // A proxy re-signs the chain with its own key, so the two only line up for a direct client.
            // Every other transport binds the chain through the encryption handshake below instead.
            if (!geyser.config().advanced().bedrock().useWaterdogpeForwarding()
                    && session.getUpstream().getSession().getPeer() instanceof NetherNetPeer) {
                if (refusedByBinding(geyser, session, TransportIdentityBinding.mismatch(
                        session.getUpstream().getSession().getPeer().getChannel(), identityPublicKey))) {
                    return;
                }
            }

            IdentityData extraData = result.identityClaims().extraData;
            String xuid = extraData.xuid;
            if (geyser.config().advanced().bedrock().useWaterdogpeForwarding()) {
                String waterdogIp = data.getWaterdogIp();
                String waterdogXuid = data.getWaterdogXuid();
                if (waterdogXuid != null && !waterdogXuid.isBlank() && waterdogIp != null && !waterdogIp.isBlank()) {
                    xuid = waterdogXuid;
                    session.getUpstream().setInetAddress(new InetSocketAddress(waterdogIp, 0));
                } else {
                    session.disconnect("Did not receive IP and xuid forwarded from the proxy!");
                    return;
                }
                // The proxy authenticated this player, so there is no key of theirs to compare.
                // Spending the binding is what stops the admission expiring under a live session,
                // and it only happens once the forwarded fields above have been accepted.
                if (refusedByBinding(geyser, session, TransportIdentityBinding.acceptForwardedIdentity(
                        session.getUpstream().getSession().getPeer().getChannel()))) {
                    return;
                }
            }
            session.setAuthData(new AuthData(extraData.displayName, extraData.identity, xuid, issuedAt, extraData.minecraftId));

            // Thanks 26.44, we love protocol bumps without protocol version bumps
            CodecProcessor.updateCodec(session.getUpstream(), data.getGameVersion());

            try {
                startEncryptionHandshake(session, identityPublicKey);
            } catch (Throwable e) {
                // An error can be thrown on older Java 8 versions about an invalid key
                if (geyser.config().debugMode()) {
                    e.printStackTrace();
                }

                sendEncryptionFailedMessage(geyser);
            }
        } catch (Exception ex) {
            session.disconnect("disconnectionScreen.internalError.cantConnect");
            throw new RuntimeException("Unable to complete login", ex);
        }
    }

    private static void startEncryptionHandshake(GeyserSession session, PublicKey key) throws Exception {
        if (session.getUpstream().getSession().getPeer() instanceof NetherNetPeer) {
            // The data channel is already encrypted by DTLS, so the peer ignores an encryption key.
            // Sending the handshake anyway would have the client encrypt what the server cannot read.
            return;
        }

        KeyPair serverKeyPair = EncryptionUtils.createKeyPair();
        byte[] token = EncryptionUtils.generateRandomToken();

        ServerToClientHandshakePacket packet = new ServerToClientHandshakePacket();
        packet.setJwt(EncryptionUtils.createHandshakeJwt(serverKeyPair, token));
        session.sendUpstreamPacketImmediately(packet);

        SecretKey encryptionKey = EncryptionUtils.getSecretKey(serverKeyPair.getPrivate(), key, token);
        session.getUpstream().getSession().enableEncryption(encryptionKey);
    }

    /**
     * The outcome of parsing a splitscreen sub-client login. Anything other than
     * {@link #SUCCESS} means the sub session must be closed and the console told.
     */
    public enum SubClientLoginResult {
        SUCCESS("joined"),
        /**
         * A console sends this for couch co-op players that have no Xbox Live sign-in. The chain
         * cannot be verified against Mojang, but the sub-client shares the connection of an
         * already authenticated primary player, so the identity is accepted as-is.
         */
        UNVERIFIED("was not signed by Mojang"),
        INVALID_CLIENT_DATA("sent client data that could not be verified"),
        NO_IDENTITY("did not send a usable username"),
        ERROR("hit an unexpected error while parsing the login");

        private final String description;

        SubClientLoginResult(String description) {
            this.description = description;
        }

        public boolean isSuccess() {
            return this == SUCCESS;
        }

        @Override
        public String toString() {
            return this.description;
        }
    }

    /**
     * Handles the login of a splitscreen sub-client that sent a {@code SubClientLoginPacket}.
     * The connection is already encrypted by the main client's login and no resource pack
     * exchange takes place for sub-clients, so this only parses the identity and client data
     * of the additional player. No encryption handshake is performed.
     * <p>
     * Unlike the primary client, a sub-client is allowed to be a guest or self-signed: on a console
     * the second couch co-op player often has no Xbox Live sign-in of their own, and the console
     * only transmits the sub-client ID and XUID for the primary player (Mojang bug MCPE-71033).
     * The sub-client still rides the already authenticated connection of its primary player, so
     * this does not allow a client that could not join as the primary player to begin with.
     */
    public static SubClientLoginResult handleSubClientLogin(GeyserSession session, AuthPayload authPayload, String clientJwt) {
        GeyserImpl geyser = session.getGeyser();
        AuthType authType = authPayload.getAuthType();
        try {
            ChainValidationResult result = EncryptionUtils.validatePayload(authPayload);
            geyser.getLogger().debug("Splitscreen login: authType=%s, signed=%s, identityClaims=%s",
                authType, result.signed(), result.identityClaims() != null);

            // Only the primary client has to pass Xbox authentication. A guest or self-signed
            // sub-client cannot be verified against Mojang, and rejecting it would lock out every
            // console whose second couch co-op player has no Microsoft account of their own. The
            // sub-client still rides the already authenticated connection of its primary player.
            boolean unverifiable = authType == AuthType.GUEST || authType == AuthType.SELF_SIGNED;
            if (!unverifiable && !result.signed() && geyser.config().advanced().bedrock().validateBedrockLogin()) {
                return SubClientLoginResult.UNVERIFIED;
            }

            ChainValidationResult.IdentityClaims identityClaims = result.identityClaims();
            if (identityClaims == null) {
                return SubClientLoginResult.NO_IDENTITY;
            }

            // Guarded because the library dereferences its JWT context without a null check,
            // which is absent on payloads that carry no signed identity
            Map<String, Object> rawIdentityClaims = result.rawIdentityClaims();
            Long rawIssuedAt = rawIdentityClaims != null ? (Long) rawIdentityClaims.get("iat") : null;
            long issuedAt = rawIssuedAt != null ? rawIssuedAt : -1;

            if (authPayload instanceof TokenPayload tokenPayload) {
                session.setToken(tokenPayload.getToken());
            } else if (authPayload instanceof CertificateChainPayload certificateChainPayload) {
                session.setCertChainData(certificateChainPayload.getChain());
            }

            // A guest sub-client has no Mojang-signed identity, so the client data cannot be
            // checked against a key we can trust. Fall back to the primary player's data instead
            // of rejecting outright; only the fields the console omits are taken from there.
            BedrockClientData data = null;
            PublicKey identityPublicKey = identityClaims.parsedIdentityPublicKey();
            if (identityPublicKey != null && clientJwt != null) {
                byte[] clientDataPayload = EncryptionUtils.verifyClientData(clientJwt, identityPublicKey);
                if (clientDataPayload != null) {
                    data = JsonUtils.fromJson(clientDataPayload, BedrockClientData.class);
                    data.setOriginalString(clientJwt);
                }
            }

            if (data == null) {
                data = session.getMainSession().getClientData();
                if (data == null) {
                    return SubClientLoginResult.INVALID_CLIENT_DATA;
                }
                geyser.getLogger().debug("Splitscreen login: reusing the primary player's client data");
            }

            // A console sends a far sparser client data blob for a sub-client than for the primary
            // player. Every field below is dereferenced without a null check somewhere on the join
            // path, so anything missing is inherited from the primary player on the same connection.
            BedrockClientData mainData = session.getMainSession().getClientData();
            if (mainData != null && data != mainData) {
                if (data.getServerAddress() == null) {
                    data.setServerAddress(mainData.getServerAddress());
                }
                if (data.getLanguageCode() == null) {
                    data.setLanguageCode(mainData.getLanguageCode());
                }
                if (data.getGameVersion() == null) {
                    data.setGameVersion(mainData.getGameVersion());
                }
                if (data.getDeviceOs() == null) {
                    data.setDeviceOs(mainData.getDeviceOs());
                }
                if (data.getUiProfile() == null) {
                    data.setUiProfile(mainData.getUiProfile());
                }
                if (data.getCurrentInputMode() == null) {
                    data.setCurrentInputMode(mainData.getCurrentInputMode());
                }
                if (data.getCapeId() == null) {
                    data.setCapeId(mainData.getCapeId());
                }
            }

            // The join address is parsed from here during the Java handshake, so it must be present
            if (data.getServerAddress() == null) {
                return SubClientLoginResult.INVALID_CLIENT_DATA;
            }
            session.setClientData(data);

            IdentityData extraData = identityClaims.extraData;
            String displayName = extraData != null ? extraData.displayName : null;
            if (displayName == null || displayName.isBlank()) {
                // Without a username there is nothing to build a stable identity from
                return SubClientLoginResult.NO_IDENTITY;
            }

            session.setAuthData(new AuthData(displayName, extraData.identity, extraData.xuid, issuedAt, extraData.minecraftId));
            return SubClientLoginResult.SUCCESS;
        } catch (Exception ex) {
            geyser.getLogger().error("Unexpected error while handling a splitscreen login!", ex);
            return SubClientLoginResult.ERROR;
        }
    }

    /**
     * Disconnects the session when the transport identity binding turned the login away.
     *
     * @param refusal why the binding refused it, or null when it did not
     * @return whether the login was refused, and the session already disconnected
     */
    private static boolean refusedByBinding(GeyserImpl geyser, GeyserSession session, String refusal) {
        if (refusal == null) {
            return false;
        }
        geyser.getLogger().info("Refused a login from " + session.getSocketAddress() + ", " + refusal);
        session.disconnect(GeyserLocale.getLocaleStringLog("geyser.network.remote.invalid_xbox_account"));
        return true;
    }

    private static void sendEncryptionFailedMessage(GeyserImpl geyser) {
        if (!HAS_SENT_ENCRYPTION_MESSAGE) {
            geyser.getLogger().warning(GeyserLocale.getLocaleStringLog("geyser.network.encryption.line_1"));
            geyser.getLogger().warning(GeyserLocale.getLocaleStringLog("geyser.network.encryption.line_2", "https://geysermc.org/supported_java"));
            HAS_SENT_ENCRYPTION_MESSAGE = true;
        }
    }

    public static void buildAndShowLoginWindow(GeyserSession session) {
        if (session.isLoggedIn()) {
            // Can happen if a window is cancelled during dimension switch
            return;
        }

        // So the time doesn't accelerate while we're here
        session.resetTimeParameters();

        session.sendForm(
                SimpleForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.locale())
                        .title("geyser.auth.login.form.notice.title")
                        .content("geyser.auth.login.form.notice.desc")
                        .button("geyser.auth.login.form.notice.btn_login.microsoft")
                        .button("geyser.auth.login.form.notice.btn_disconnect")
                        .closedOrInvalidResultHandler(() -> buildAndShowLoginWindow(session))
                        .validResultHandler((response) -> {
                            if (response.clickedButtonId() == 0) {
                                session.authenticateWithMicrosoftCode();
                                return;
                            }

                            session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.locale()));
                        }));
    }

    /**
     * Build a window that explains the user's credentials will be saved to the system.
     */
    public static void buildAndShowConsentWindow(GeyserSession session) {
        String locale = session.locale();

        session.sendForm(
                SimpleForm.builder()
                        .translator(LoginEncryptionUtils::translate, locale)
                        .title("%gui.signIn")
                        .content("""
                                geyser.auth.login.save_token.warning

                                geyser.auth.login.save_token.proceed""")
                        .button("%gui.ok")
                        .button("%gui.decline")
                        .resultHandler(authenticateOrKickHandler(session))
        );
    }

    public static void buildAndShowTokenExpiredWindow(GeyserSession session) {
        String locale = session.locale();

        session.sendForm(
                SimpleForm.builder()
                        .translator(LoginEncryptionUtils::translate, locale)
                        .title("geyser.auth.login.form.expired")
                        .content("""
                                geyser.auth.login.save_token.expired

                                geyser.auth.login.save_token.proceed""")
                        .button("%gui.ok")
                        .resultHandler(authenticateOrKickHandler(session))
        );
    }

    private static BiConsumer<SimpleForm, FormResponseResult<SimpleFormResponse>> authenticateOrKickHandler(GeyserSession session) {
        return (form, genericResult) -> {
            if (genericResult instanceof ValidFormResponseResult<SimpleFormResponse> result &&
                    result.response().clickedButtonId() == 0) {
                session.authenticateWithMicrosoftCode(true);
            } else {
                session.disconnect("%disconnect.quitting");
            }
        };
    }

    /**
     * Shows the code that a user must input into their browser
     */
    public static void buildAndShowMicrosoftCodeWindow(GeyserSession session, MsaDeviceCode msCode) {
        String locale = session.locale();

        StringBuilder message = new StringBuilder("%xbox.signin.website\n")
                .append(ChatColor.AQUA)
                .append("%xbox.signin.url")
                .append(ChatColor.RESET)
                .append("\n%xbox.signin.enterCode\n")
                .append(ChatColor.GREEN)
                .append(msCode.getUserCode());
        int timeout = session.getGeyser().config().pendingAuthenticationTimeout();
        if (timeout != 0) {
            message.append("\n\n")
                    .append(ChatColor.RESET)
                    .append(GeyserLocale.getPlayerLocaleString("geyser.auth.login.timeout", session.locale(), String.valueOf(timeout)));
        }

        session.sendForm(
                ModalForm.builder()
                        .title("%xbox.signin")
                        .content(message.toString())
                        .button1("%gui.done")
                        .button2("%menu.disconnect")
                        .closedOrInvalidResultHandler(() -> buildAndShowLoginWindow(session))
                        .validResultHandler((response) -> {
                            if (response.clickedButtonId() == 1) {
                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", locale));
                            }
                        })
        );
    }

    /*
    This checks per line if there is something to be translated, and it skips Bedrock translation keys (%)
     */
    private static String translate(String key, String locale) {
        StringBuilder newValue = new StringBuilder();
        int previousIndex = 0;
        while (previousIndex < key.length()) {
            int nextIndex = key.indexOf('\n', previousIndex);
            int endIndex = nextIndex == -1 ? key.length() : nextIndex;

            // if there is more to this line than just a new line char
            if (endIndex - previousIndex > 1) {
                String substring = key.substring(previousIndex, endIndex);
                if (key.charAt(previousIndex) != '%') {
                    newValue.append(GeyserLocale.getPlayerLocaleString(substring, locale));
                } else {
                    newValue.append(substring);
                }
            }
            newValue.append('\n');

            previousIndex = endIndex + 1;
        }
        return newValue.toString();
    }
}
