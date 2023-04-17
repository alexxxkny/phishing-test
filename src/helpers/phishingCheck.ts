import Email from "./email";
import data from '../data/suspicious.json';
import moment from "moment";

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
    SuspiciousPhrase,
    TimeTravel,
    DifferentNameInText,
    DifferentNameInReceiver
}

interface IKeyToReasons {
    [index: string]: PhishingWarningReason[]
}

export const KeyToReasons: IKeyToReasons = {
    'from_email': [PhishingWarningReason.DomainName],
    'from_name': [PhishingWarningReason.DomainName],
    'to_name': [PhishingWarningReason.DifferentNameInReceiver],
    'text': [PhishingWarningReason.Link, PhishingWarningReason.SuspiciousPhrase, PhishingWarningReason.TimeTravel, PhishingWarningReason.DifferentNameInText],
    'attachment': [PhishingWarningReason.Attachment]
}

export class PhishingCheck {
    readonly email: Email;
    readonly warnings: {
        reason: PhishingWarningReason,
        comment: string,
        highlight?: string,
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
                highlight: domainName,
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
                    highlight: link,
                    comment: "Похоже что домен ссылки в сообщении отличается от домена компании, это может говорить о том, что это вредоносная ссылка!"
                });
            }
        }

        // Searching for sentances with suspicious phrases
        data.suspiciousPhrases.forEach(({phrase, comment}) => {
            const phraseSentenseRegExp = new RegExp(`\\. ([\\p{sc=Cyrillic}\\s]*${phrase}[\\p{sc=Cyrillic}\\s]*(\\.|!{3}))`, 'u');
            const sentenceMatch = this.email.text.match(phraseSentenseRegExp);

            if (typeof sentenceMatch?.[1] === "string") {
                const sentence = sentenceMatch[1];
                this.warnings.push({
                    reason: PhishingWarningReason.SuspiciousPhrase,
                    highlight: sentence,
                    comment: comment
                });
            }
        });

        // Date check
        const dateRegExp = /\d{2}.\d{2}.\d{4}/;
        const dateMatch = this.email.text.match(dateRegExp);
        if(dateMatch) {
            const textDate = moment(dateMatch[0], 'DD.MM.YYYY').toDate();
            const date = new Date(this.email.date);
            if (textDate > date) {
                this.warnings.push({
                    reason: PhishingWarningReason.TimeTravel,
                    highlight: dateMatch[0],
                    comment: "Они знают будущее! ШОК!"
                })    
            }
        }

        //Name check
        const textNameRegExp = /^Уважаемый\s([\p{sc=Cyrillic}]+),/u;
        const receiverNameRegExp = /^(\p{sc=Cyrillic}+)\s/u;
        const textNameMatch = this.email.text.match(textNameRegExp);
        const receiverNameMatch = this.email.to_name.match(receiverNameRegExp);
        if(textNameMatch && receiverNameMatch) {
            const textName = textNameMatch[1]
            const receiverName = receiverNameMatch[1];
            if(textName !== receiverName) {
                this.warnings.push({
                    reason: PhishingWarningReason.DifferentNameInText,
                    highlight: textName,
                    comment: "Имя получателя и имя обращения различаются!"
                });
                this.warnings.push({
                    reason: PhishingWarningReason.DifferentNameInReceiver,
                    highlight: receiverName,
                    comment: "Имя получателя и имя обращения различаются!"
                });
            }
        }
        
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