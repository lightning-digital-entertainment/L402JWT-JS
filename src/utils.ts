import { createHash } from "crypto";
import * as boltDecoder from "light-bolt11-decoder";


export function getSHA256(content: string) {
    return createHash("sha256").update(content).digest("hex");
}

export function getBolt11Section(sectionName: "payment_hash", bolt11Invoice: string) {
    const result = boltDecoder.decode(bolt11Invoice);
    for (let i = 0; i < result.sections.length; i++) {
        if (result.sections[i].name === sectionName) {
            console.log(result.sections[i].value);
            return result.sections[i].value;
        }
    }
}
