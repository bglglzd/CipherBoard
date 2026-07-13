/*
 * Copyright (C) 2013 The Android Open Source Project
 * modified
 * SPDX-License-Identifier: Apache-2.0 AND GPL-3.0-only
 */

package helium314.keyboard.latin.common;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import helium314.keyboard.latin.utils.ExecutorUtils;

/**
 * A simple class to help with removing directories recursively.
 */
public class FileUtils {

    public static boolean deleteRecursively(final File path) {
        if (path.isDirectory()) {
            final File[] files = path.listFiles();
            if (files != null) {
                for (final File child : files) {
                    deleteRecursively(child);
                }
            }
        }
        return path.delete();
    }

    public static boolean deleteFilteredFiles(final File dir, final FilenameFilter fileNameFilter) {
        if (!dir.isDirectory()) {
            return false;
        }
        final File[] files = dir.listFiles(fileNameFilter);
        if (files == null) {
            return false;
        }
        boolean hasDeletedAllFiles = true;
        for (final File file : files) {
            if (!deleteRecursively(file)) {
                hasDeletedAllFiles = false;
            }
        }
        return hasDeletedAllFiles;
    }

    /**
     *  copy data to file on different thread to avoid NetworkOnMainThreadException
     *  still effectively blocking, as we only use small files which are mostly stored locally
     */
    public static void copyContentUriToNewFile(final Uri uri, final Context context, final File outfile) throws IOException {
        if (!"content".equals(uri.getScheme())) {
            throw new IOException("only content URIs are accepted");
        }
        final File parent = outfile.getParentFile();
        if (parent == null || (!parent.exists() && !parent.mkdirs())) {
            throw new IOException("could not create import directory");
        }
        final File temporary = File.createTempFile("cb-import-", ".tmp", parent);
        final CountDownLatch wait = new CountDownLatch(1);
        final AtomicBoolean cancelled = new AtomicBoolean(false);
        final AtomicReference<InputStream> activeInput = new AtomicReference<>();
        final AtomicReference<IOException> failure = new AtomicReference<>();
        ExecutorUtils.getBackgroundExecutor(ExecutorUtils.KEYBOARD).execute(() -> {
            try (InputStream input = context.getContentResolver().openInputStream(uri)) {
                if (input == null) throw new IOException("content provider returned no stream");
                activeInput.set(input);
                if (cancelled.get()) throw new IOException("content read timed out");
                copyStreamToNewFile(input, temporary);
            } catch (IOException e) {
                failure.set(e);
                temporary.delete();
            } finally {
                activeInput.set(null);
                wait.countDown();
            }
        });
        final boolean completed;
        try {
            completed = wait.await(CONTENT_READ_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cancelled.set(true);
            closeQuietly(activeInput.get());
            temporary.delete();
            throw new IOException("content read interrupted", e);
        }
        if (!completed) {
            cancelled.set(true);
            closeQuietly(activeInput.get());
            temporary.delete();
            throw new IOException("content read timed out");
        }
        final IOException error = failure.get();
        if (error != null) {
            temporary.delete();
            throw new IOException("could not copy from content URI", error);
        }
        if ((outfile.exists() && !outfile.delete()) || !temporary.renameTo(outfile)) {
            temporary.delete();
            throw new IOException("could not commit imported file");
        }
    }

    public static void copyStreamToNewFile(final InputStream in, final File outfile) throws IOException {
        File parentFile = outfile.getParentFile();
        if (parentFile == null || (!parentFile.exists() && !parentFile.mkdirs())) {
            throw new IOException("could not create parent folder");
        }
        try (FileOutputStream out = new FileOutputStream(outfile)) {
            copyStreamToOtherStream(in, out);
        } catch (IOException error) {
            outfile.delete();
            throw error;
        }
    }

    public static void copyStreamToOtherStream(final InputStream in, final OutputStream out) throws IOException {
        if (in == null) throw new IOException("input stream is unavailable");
        final byte[] buf = new byte[8192];
        long total = 0;
        try {
            int len;
            while ((len = in.read(buf)) != -1) {
                if (len == 0) continue;
                total += len;
                if (total > MAX_IMPORTED_FILE_BYTES) {
                    throw new IOException("import exceeds the file size limit");
                }
                out.write(buf, 0, len);
            }
            out.flush();
        } finally {
            Arrays.fill(buf, (byte) 0);
        }
    }

    private static void closeQuietly(final InputStream input) {
        if (input == null) return;
        try {
            input.close();
        } catch (IOException ignored) {
            // The original timeout or provider error remains authoritative.
        }
    }

    private static final long MAX_IMPORTED_FILE_BYTES = 128L * 1024L * 1024L;
    private static final long CONTENT_READ_TIMEOUT_SECONDS = 15L;

}
