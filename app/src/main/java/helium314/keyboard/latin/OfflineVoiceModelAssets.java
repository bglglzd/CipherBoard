// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin;

import android.content.Context;
import android.content.res.AssetManager;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Copies a packaged, checksum-pinned Vosk model into app-private storage. */
final class OfflineVoiceModelAssets {
    private static final String ASSET_ROOT = "voice_models";
    private static final Object COPY_LOCK = new Object();

    private OfflineVoiceModelAssets() {}

    @NonNull
    static File prepare(@NonNull final Context context, @NonNull final String language)
            throws IOException {
        if (!"en".equals(language) && !"ru".equals(language)) {
            throw new IOException("Unsupported offline voice language");
        }
        final AssetManager assets = context.getAssets();
        final String assetPath = ASSET_ROOT + "/" + language;
        final String modelHash = readSmallAsset(assets, assetPath + "/.cipherboard-model-sha256");
        if (!modelHash.matches("[0-9a-f]{64}")) {
            throw new IOException("Invalid packaged voice model marker");
        }

        final File modelsDirectory = new File(context.getNoBackupFilesDir(), "offline-voice-models");
        final File installed = new File(modelsDirectory, language + "-" + modelHash.substring(0, 16));
        synchronized (COPY_LOCK) {
            if (isComplete(installed, modelHash)) return installed;
            if (!modelsDirectory.isDirectory() && !modelsDirectory.mkdirs()) {
                throw new IOException("Could not create private model directory");
            }
            final File staging = new File(modelsDirectory, language + "-staging");
            deleteTree(staging);
            if (!staging.mkdirs()) throw new IOException("Could not stage offline voice model");
            try {
                copyAssetTree(assets, assetPath, staging);
                if (!new File(staging, "am/final.mdl").isFile()
                        || !new File(staging, "conf/model.conf").isFile()) {
                    throw new IOException("Packaged offline voice model is incomplete");
                }
                writeMarker(new File(staging, ".installed-sha256"), modelHash);
                deleteTree(installed);
                if (!staging.renameTo(installed)) {
                    throw new IOException("Could not install offline voice model");
                }
                removeSupersededModels(modelsDirectory, language, installed);
                return installed;
            } catch (IOException | RuntimeException exception) {
                deleteTree(staging);
                throw exception;
            }
        }
    }

    private static boolean isComplete(final File directory, final String expectedHash) {
        try {
            return directory.isDirectory()
                    && new File(directory, "am/final.mdl").isFile()
                    && new File(directory, "conf/model.conf").isFile()
                    && expectedHash.equals(readSmallFile(
                            new File(directory, ".installed-sha256")).trim());
        } catch (IOException exception) {
            return false;
        }
    }

    private static String readSmallAsset(final AssetManager assets, final String path)
            throws IOException {
        try (InputStream input = assets.open(path)) {
            return readSmallStream(input).trim();
        }
    }

    private static String readSmallFile(final File path) throws IOException {
        try (InputStream input = new FileInputStream(path)) {
            return readSmallStream(input);
        }
    }

    private static String readSmallStream(final InputStream input) throws IOException {
        final byte[] value = new byte[128];
        int length = 0;
        while (length < value.length) {
            final int read = input.read(value, length, value.length - length);
            if (read < 0) break;
            length += read;
        }
        if (input.read() != -1) throw new IOException("Voice model marker is too large");
        return new String(value, 0, length, StandardCharsets.US_ASCII);
    }

    private static void copyAssetTree(
            final AssetManager assets, final String source, final File destination)
            throws IOException {
        final String[] children = assets.list(source);
        if (children != null && children.length > 0) {
            if (!destination.isDirectory() && !destination.mkdirs()) {
                throw new IOException("Could not create model directory");
            }
            for (String child : children) {
                copyAssetTree(assets, source + "/" + child, new File(destination, child));
            }
            return;
        }
        try (InputStream input = assets.open(source);
                FileOutputStream output = new FileOutputStream(destination)) {
            final byte[] buffer = new byte[32 * 1024];
            while (true) {
                final int read = input.read(buffer);
                if (read < 0) break;
                output.write(buffer, 0, read);
            }
            output.getFD().sync();
        }
    }

    private static void writeMarker(final File marker, final String value) throws IOException {
        try (FileOutputStream output = new FileOutputStream(marker)) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
    }

    private static void removeSupersededModels(
            final File parent, final String language, final File current) {
        final File[] entries = parent.listFiles();
        if (entries == null) return;
        final String prefix = language + "-";
        for (File entry : entries) {
            if (!entry.equals(current) && entry.getName().startsWith(prefix)) deleteTree(entry);
        }
    }

    private static void deleteTree(final File path) {
        if (!path.exists()) return;
        final File[] children = path.listFiles();
        if (children != null) {
            for (File child : children) deleteTree(child);
        }
        // A failed cleanup is handled by the subsequent mkdir/move checks.
        path.delete();
    }
}
