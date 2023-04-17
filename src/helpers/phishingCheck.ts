import Email from "./email";
import data from '../data/suspicious.json';

const LinkRegExp = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/;
const DomainRegExp = /@(\w+.\w{2,3})$/;

export enum PhishingCheckConclusion {
    Safe,
    Suspicious
}

export enum PhishingWarningReason {
    DomainName,
    Link,
    Attachment,
    SuspiciousPhrase
}

interface IKeyToReasons {
    [index: string]: PhishingWarningReason[]
}

export const KeyToReasons: IKeyToReasons = {
    'from_email': [PhishingWarningReason.DomainName],
    'from_name': [PhishingWarningReason.DomainName],
    'text': [PhishingWarningReason.Link, PhishingWarningReason.SuspiciousPhrase],
    'attachment': [PhishingWarningReason.Attachment]
}

export class PhishingCheck {
    readonly email: Email;
    readonly warnings: {
        reason: PhishingWarningReason,
        comment: string,
        domainName?: string,
        link?: string,
        sentence?: string
    }[]

    constructor(email: Email) {
        this.email = email;
        this.warnings = [];
        this.check();
    }

    public getFinalConclusion(): PhishingCheckConclusion {
        return this.warnings.length > 0 ? PhishingCheckConclusion.Suspicious : PhishingCheckConclusion.Safe;
    }

    private check() {
        const domain = this.tryGetDomain();
        const domainName = domain.split('.')[0];

        // Domain name expected to be contained in sender name if an email was sent from a company
        const senderNameContainsDomainName = this.email.from_name.search(new RegExp(`${domainName}`, 'i')) !== -1;
        if (!senderNameContainsDomainName) {
            this.warnings.push({
                reason: PhishingWarningReason.DomainName,
                domainName: domainName,
                comment: "Похоже что почтовый домен не принадлежит указанной компании, это может говорить о том, что письмо поддельное!"
            });
        }

        // Links expected to end with corresponding domain
        const linkMatch = this.email.text.match(LinkRegExp);
        if (linkMatch) {
            const link = linkMatch[0];
            const linkContainsMailDomain = link.search(new RegExp(`${domainName}`, 'i')) !== -1;
            if (!linkContainsMailDomain) {
                this.warnings.push({
                    reason: PhishingWarningReason.Link,
                    link: link,
                    comment: "Похоже что домен ссылки в сообщении отличается от домена компании, это может говорить о том, что это вредоносная ссылка!"
                });
            }
        }

        // Searching for sentances with suspicious phrases
        data.suspiciousPhrases.forEach(({phrase, comment}) => {
            const phraseSentenseRegExp = new RegExp(`\\. ([\\p{sc=Cyrillic}\\s]*${phrase}[\\p{sc=Cyrillic}\\s]*\\.)`, 'u');
            const sentenceMatch = this.email.text.match(phraseSentenseRegExp);

            if (typeof sentenceMatch?.[1] === "string") {
                const sentence = sentenceMatch[1];
                this.warnings.push({
                    reason: PhishingWarningReason.SuspiciousPhrase,
                    sentence: sentence,
                    comment: comment
                });
            }
        });
        
        // Attachment check
        if (this.email.attachment.length > 0) {
            this.warnings.push({
                reason: PhishingWarningReason.Attachment,
                comment: "Побуждение к открытию прикрепленных в письме файлов может быть попыткой мошенничества! Данный файл может оказаться вирусом!"
            })
        }
    }
    
    private tryGetDomain(): string {
        const match = this.email.from_email.match(DomainRegExp);
        if (typeof match?.[1] !== "string") {
            throw new Error(`Domain name was not obtained from "${this.email.from_email}"!`);
        }
        return match[1];
    }
}