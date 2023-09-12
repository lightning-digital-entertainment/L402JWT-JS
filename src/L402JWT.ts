import * as jwt from "jsonwebtoken";
import { getBolt11Section, getSHA256 } from "./utils";

type JWTPayload = {
    paymentHash: string;
    bodyHash?: string;
    expiresAt?: number;
};

class L402JWT {
    paymentHash?: string;
    paymentRequest?: string;
    preimage?: string;
    bodyHash?: string;
    expiresAt?: number;
    token?: string;

    private createJWT(secret: string) {
        if (!this.paymentHash) {
            throw new Error("Specify a payment hash to generate a L402JWT");
        }
        const payload: JWTPayload = { paymentHash: this.paymentHash };
        if (this.bodyHash) {
            payload.bodyHash = this.bodyHash;
        }
        if (this.expiresAt) {
            payload.expiresAt = this.expiresAt;
        }
        return jwt.sign(payload, secret);
    }

    createFromBolt11(bolt11Invoice: string) {
        this.paymentRequest = bolt11Invoice;
        this.paymentHash = getBolt11Section("payment_hash", bolt11Invoice);
        return this;
    }

    createFromJwt(token: string) {
        try {
            const payload = jwt.decode(token, { json: true }) as JWTPayload;
            if (!payload || !payload.paymentHash) {
                throw new Error(
                    "Valid L402JWT requires at least a payment hash property"
                );
            }
            this.paymentHash = payload.paymentHash;
            if (payload.bodyHash) {
                this.bodyHash = payload.bodyHash;
            }
            if (payload.expiresAt) {
                payload.expiresAt;
            }
        } catch {
            throw new Error("Could not decode JWT");
        }
    }

    createFromAuthHeader(basicAuthHeader: string) {
        if (!basicAuthHeader) {
            throw new Error("No authorization header passed");
        }
        const l402jwt = basicAuthHeader.split(" ").pop();
        if (!l402jwt) {
            throw new Error("Invalid L402JWT authorization header");
        }
        const [token, preimage] = l402jwt.split(":");
        if (!token || !preimage) {
            throw new Error("Invalid L402JWT authorization header");
        }
        try {
            const payload = jwt.decode(token, { json: true }) as JWTPayload;
            if (!payload || !payload.paymentHash || !preimage) {
                throw new Error(
                    "Valid authorization header requires at least payment hash property and preimage"
                );
            }
            this.paymentHash = payload.paymentHash;
            this.preimage = preimage;
            this.token = token;
            if (payload.bodyHash) {
                this.bodyHash = payload.bodyHash;
            }
            if (payload.expiresAt) {
                payload.expiresAt;
            }
            return this;
        } catch {
            throw new Error("Could not decode token");
        }
    }

    getChallengeHeader(secret: string) {
        return `L402 JWT="${this.createJWT(secret)}", invoice="${
            this.paymentRequest
        }`;
    }

    addBodyHashRestriction(stringifiedBody: string) {
        this.bodyHash = getSHA256(stringifiedBody);
        return this;
    }

    addExpiry(secondsValidFor: number) {
        this.expiresAt = Math.floor(Date.now() / 1000) + secondsValidFor;
        return this;
    }

    isExpired() {
        if (!this.expiresAt) {
            return true;
        }
        return Math.floor(Date.now() / 1000) < this.expiresAt;
    }

    isPaid() {
        if (!this.paymentHash || !this.preimage) {
            return false;
        }
        return getSHA256(this.preimage) === this.paymentHash;
    }

    isValidBody(stringifiedBody: string) {
        if (this.bodyHash) {
            return true;
        }
        return getSHA256(stringifiedBody) === this.bodyHash; 
    }
}

export default L402JWT;
