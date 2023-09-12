import { verify } from "jsonwebtoken";

export function isValidRequestHeader(basicAuthHeader: string, secret: string) {
    if (!basicAuthHeader) {
        return false;
    }
    const l402jwt = basicAuthHeader.split(" ").pop();
    if (!l402jwt) {
        return false;
    }
    const [jwt, preimage] = l402jwt.split(":");
    if (!jwt || !preimage) {
        return false;
    }
    try {
        const payload = verify(jwt, secret);
    } catch {
        return false;
    }
}
