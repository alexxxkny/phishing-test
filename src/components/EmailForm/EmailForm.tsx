import './EmailForm.css';
import {PhishingCheck, PhishingCheckConclusion, KeyToReasons, PhishingWarningReason} from '../../helpers/phishingCheck';
import parse from 'html-react-parser';

function EmailForm({phishingCheck, onButtonClick} : {phishingCheck: PhishingCheck | null, onButtonClick: any}) {
  if (phishingCheck === null) {
    return (
        <div className="form">
          <div className="form-header">
            <button className="next-btn"></button>
          </div>
        </div>
    )
  }

  const email = phishingCheck.email;
  const warnings = phishingCheck.warnings;
  console.log(warnings);
  const rows = Object.entries(email).map(([key, originalValue]) => {
    const keyWarningReasons = KeyToReasons[key] ?? [];
    const relatedWarnings = warnings.filter((w) => {
      return keyWarningReasons.includes(w.reason);
    })
    const hasWarnings = relatedWarnings.length > 0;

    let value = originalValue;
    relatedWarnings.forEach((w) => {
      switch (w.reason) {
        case PhishingWarningReason.DomainName:
          if(!w.domainName) break;
          const domainName = w.domainName;
          value = value.replace(
            domainName,
            `<span className='warning-text'>${domainName}</span>`
          );
          break;
        case PhishingWarningReason.Link:
          if(!w.link) break;
          const link = w.link;
          value = value.replace(
            link,
            `<span className='warning-text'>${link}</span>`
          );
          break;
        case PhishingWarningReason.SuspiciousPhrase:
          if(!w.sentence) break;
          const sentence = w.sentence;
          value = value.replace(
            sentence,
            `<span className='warning-text'>${sentence}</span>`
          );
          break;
      }
    });
    const warningBlocks = relatedWarnings.map((w, index) => {
        return <div key={index} className="content-row__warning">{w.comment}</div>;
    });

    return (
        <div key={key} className="content-row">
            <div className={`content-row__key ${hasWarnings ? "warning-text" : ""}`}>{key + ':'}</div>
            <div className="content-row__value-box">
                <div className={`content-row__value ${hasWarnings ? "content-row__value-box_warning" : ""}`}><p>{parse(value)}</p></div>
                {warningBlocks}
            </div>
        </div>
    )
  })

  return (
    <div className="form">
      <div className="form-header">
        <button className="next-btn" onClick={onButtonClick}></button>
      </div>
      <div className="split-row">Сообщение</div>
      {rows}
      {
        phishingCheck.getFinalConclusion() === PhishingCheckConclusion.Safe ?
        <div className="split-row">Вердикт: <span className='safe'>Все чисто</span></div> :
        <div className="split-row">Вердикт: <span className='warning-text'>Подозрительное -.-</span></div>
      }
    </div>
  );
}

export default EmailForm;
