// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin;

import android.view.inputmethod.EditorInfo;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Objects;

/**
 * Identifies the editor that explicitly requested the microphone permission flow.
 *
 * <p>Android may replace the {@link android.view.inputmethod.InputConnection} while the
 * permission activity temporarily covers the host editor, so the pending request cannot safely
 * use connection object identity. Once the same editor metadata returns, LatinIME binds the
 * actual dictation session to the new live connection and requires exact connection identity
 * before committing any recognized text.</p>
 */
final class OfflineVoiceEditorScope {
    @NonNull private final String packageName;
    private final int uid;
    private final int fieldId;
    @Nullable private final String fieldName;
    private final int inputType;
    private final int imeOptions;
    @Nullable private final String privateImeOptions;

    private OfflineVoiceEditorScope(
            @NonNull final String packageName,
            final int uid,
            final int fieldId,
            @Nullable final String fieldName,
            final int inputType,
            final int imeOptions,
            @Nullable final String privateImeOptions) {
        this.packageName = packageName;
        this.uid = uid;
        this.fieldId = fieldId;
        this.fieldName = fieldName;
        this.inputType = inputType;
        this.imeOptions = imeOptions;
        this.privateImeOptions = privateImeOptions;
    }

    @Nullable
    static OfflineVoiceEditorScope from(@Nullable final EditorInfo editorInfo, final int uid) {
        if (editorInfo == null || editorInfo.packageName == null
                || editorInfo.packageName.trim().isEmpty() || uid < 0) {
            return null;
        }
        return new OfflineVoiceEditorScope(
                editorInfo.packageName,
                uid,
                editorInfo.fieldId,
                editorInfo.fieldName,
                editorInfo.inputType,
                editorInfo.imeOptions,
                editorInfo.privateImeOptions);
    }

    boolean matches(@Nullable final EditorInfo editorInfo, final int currentUid) {
        return editorInfo != null
                && uid == currentUid
                && packageName.equals(editorInfo.packageName)
                && fieldId == editorInfo.fieldId
                && Objects.equals(fieldName, editorInfo.fieldName)
                && inputType == editorInfo.inputType
                && imeOptions == editorInfo.imeOptions
                && Objects.equals(privateImeOptions, editorInfo.privateImeOptions);
    }
}
