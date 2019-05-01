/*
 * Copyright (c) 2018 Mastercard
 * Copyright (c) 2018 Gluu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.gluu.oxauth.fido2.exception;

import org.gluu.oxauth.fido2.model.error.Fido2RPError;

public class Fido2RPRuntimeException extends RuntimeException {

    private static final long serialVersionUID = -518563205092295773L;

    private final String status;
    private final String errorMessage;

    public Fido2RPRuntimeException(String errorMessage) {
        super(errorMessage);
        this.status = "failed";
        this.errorMessage = errorMessage;
    }

    public Fido2RPRuntimeException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
        this.status = "failed";
        this.errorMessage = errorMessage;
    }

    public Fido2RPRuntimeException(String status, String errorMessage) {
        super(errorMessage);
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public Fido2RPRuntimeException(String status, String errorMessage, Throwable cause) {
        super(errorMessage, cause);
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public Fido2RPError getFormattedMessage() {
        return new Fido2RPError(status, errorMessage);
    }
}
