/*
 * Copyright (c) 2019-2026 GeyserMC. http://geysermc.org
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

package org.geysermc.geyser.network.bedrock;

import net.kyori.adventure.text.Component;
import org.cloudburstmc.protocol.bedrock.BedrockServerSession;
import org.cloudburstmc.protocol.bedrock.packet.BedrockPacket;
import org.cloudburstmc.protocol.bedrock.packet.DisconnectPacket;
import org.cloudburstmc.protocol.bedrock.packet.PlayStatusPacket;
import org.cloudburstmc.protocol.bedrock.packet.SubClientLoginPacket;
import org.cloudburstmc.protocol.common.PacketSignal;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.api.event.bedrock.SessionInitializeEvent;
import org.geysermc.geyser.api.network.AuthType;
import org.geysermc.geyser.registry.BlockRegistries;
import org.geysermc.geyser.registry.Registries;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.session.auth.AuthData;
import org.geysermc.geyser.util.LoginEncryptionUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Handles the packets of a splitscreen (couch co-op) sub-client on a Bedrock console.
 * <p>
 * The console shares one RakNet connection between all local players. The primary player performs
 * the regular login, encryption handshake and resource pack exchange, so a sub-client only needs to
 * parse its own identity and then log into the Java server like any other player.
 */
public class SubClientUpstreamPacketHandler extends LoggingPacketHandler {
    private final BedrockServerSession upstream;
    private final GeyserSession mainSession;
    /**
     * Recreated whenever the splitscreen player leaves and rejoins; super keeps the first instance.
     */
    private GeyserSession subSession;
    private boolean loginCompleted;

    public SubClientUpstreamPacketHandler(GeyserImpl geyser, BedrockServerSession upstream,
                                          GeyserSession subSession, GeyserSession mainSession) {
        super(geyser, subSession);
        this.upstream = upstream;
        this.subSession = subSession;
        this.mainSession = mainSession;
    }

    @Override
    PacketSignal defaultHandler(BedrockPacket packet) {
        if (subSession == null || subSession.isClosed()) {
            return PacketSignal.HANDLED;
        }
        Registries.BEDROCK_PACKET_TRANSLATORS.translate(packet.getClass(), packet, subSession, false);
        return PacketSignal.HANDLED;
    }

    @Override
    public PacketSignal handle(SubClientLoginPacket packet) {
        if (geyser.isShuttingDown() || geyser.isReloading()) {
            return PacketSignal.HANDLED;
        }

        if (mainSession.isClosed()) {
            geyser.getLogger().debug("Refusing splitscreen login: the primary player is no longer connected.");
            return PacketSignal.HANDLED;
        }

        if (subSession.isClosed()) {
            // The splitscreen player left and rejoined; build a fresh session on the shared connection.
            // The Bedrock session keeps its sub-client ID, so the replacement keeps routing correctly.
            subSession = new GeyserSession(geyser, upstream, mainSession.getTickEventLoop(), mainSession);
            loginCompleted = false;
        } else if (loginCompleted) {
            geyser.getLogger().debug("Ignoring duplicate splitscreen login packet!");
            return PacketSignal.HANDLED;
        }

        if (!LoginEncryptionUtils.handleSubClientLogin(subSession, packet.getAuthPayload(), packet.getClientJwt())) {
            // We cannot show a kick message to a sub-client without also kicking the primary player,
            // so this only shows up in the console log
            geyser.getLogger().info("A splitscreen player failed to sign in! They must be signed into their "
                + "own Microsoft account that has joined the Java server before. ("
                + subSession.getUpstream().getAddress().getAddress() + ")");
            return PacketSignal.HANDLED;
        }

        // Consoles do not send the XUID of splitscreen players (Mojang bug MCPE-71033), so generate a
        // stable one from the player's username to keep Floodgate identities and server data consistent
        AuthData authData = subSession.getAuthData();
        if (authData.xuid() == null || authData.xuid().isEmpty()
            || geyser.getSessionManager().isXuidAlreadyPending(authData.xuid())
            || geyser.getSessionManager().sessionByXuid(authData.xuid()) != null) {
            String generatedXuid = generateXuid(authData.name());
            geyser.getLogger().info(authData.name() + " is playing splitscreen; using generated XUID " + generatedXuid
                + " since the console did not send one (MCPE-71033).");
            subSession.setAuthData(new AuthData(authData.name(), authData.uuid(), generatedXuid,
                authData.issuedAt(), authData.playFabId()));
        }

        if (geyser.getSessionManager().isXuidAlreadyPending(subSession.xuid())
            || geyser.getSessionManager().sessionByXuid(subSession.xuid()) != null) {
            geyser.getLogger().info(subSession.bedrockUsername() + " is already logged in! (splitscreen)");
            return PacketSignal.HANDLED;
        }

        // The main client already negotiated the codec, so copy its version for the mappings
        int protocolVersion = mainSession.protocolVersion();
        subSession.setBlockMappings(BlockRegistries.BLOCKS.forVersion(protocolVersion));
        subSession.setItemMappings(Registries.ITEMS.forVersion(protocolVersion));

        geyser.getSessionManager().addPendingSession(subSession);
        geyser.eventBus().fire(new SessionInitializeEvent(subSession));
        mainSession.getSubSessions().add(subSession);
        loginCompleted = true;

        // The primary player already completed the resource pack exchange for this connection
        PlayStatusPacket playStatus = new PlayStatusPacket();
        playStatus.setStatus(PlayStatusPacket.Status.LOGIN_SUCCESS);
        subSession.sendUpstreamPacket(playStatus);

        if (geyser.config().java().authType() != AuthType.ONLINE) {
            subSession.authenticate(subSession.getAuthData().name());
        } else {
            // Microsoft device code auth isn't practical for a second controller; the player joins
            // the white world and Floodgate/saved auth must resolve the account
            geyser.getLogger().info(subSession.bedrockUsername() + " is playing splitscreen with online authentication; "
                + "they will spawn in the white world and require Floodgate or a saved login.");
            subSession.connect();
        }

        geyser.getLogger().info(subSession.bedrockUsername() + " (" + subSession.protocolVersion() + ") joined via splitscreen.");
        return PacketSignal.HANDLED;
    }

    @Override
    public PacketSignal handle(DisconnectPacket packet) {
        // The splitscreen player left on the console side
        leave();
        return PacketSignal.HANDLED;
    }

    @Override
    public void onDisconnect(CharSequence reason) {
        // Only reached when the whole console connection closes, not when a single player leaves
        leave();
    }

    private void leave() {
        if (subSession != null && !subSession.isClosed()) {
            subSession.disconnect(Component.text("Splitscreen player left"));
        }
    }

    /**
     * Generates a stable numeric XUID from a player's username. Deterministic so the same player
     * always maps to the same identity for Floodgate, while staying unique across players.
     */
    private static String generateXuid(String name) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(("geyser-splitscreen:" + name.toLowerCase(Locale.ROOT))
                .getBytes(StandardCharsets.UTF_8));
            long value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (hash[i] & 0xFF);
            }
            // Keep the value within the range of a real XUID
            return Long.toString(Math.floorMod(value, 800_000_000_000_000L) + 100_000_000_000_000L);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is required by the Java platform", e);
        }
    }
}
