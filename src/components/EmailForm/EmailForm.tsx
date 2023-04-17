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
  
  const rows = Object.entries(email).map(([key, originalValue]) => {
    const keyWarningReasons = KeyToReasons[key] ?? [];
    const relatedWarnings = warnings.filter((w) => {
      return keyWarningReasons.includes(w.reason);
    })
    const hasWarnings = relatedWarnings.length > 0;

    let value = originalValue;
    relatedWarnings.forEach((w) => {
      if(w.highlight) {
        const highlight = w.highlight;
        value = value.replace(
          highlight,
          `<span className='warning-text'>${highlight}</span>`
        );
      }
    });

    const warningBlocks = relatedWarnings.map((w, index) => {
        return <div key={index} className="content-row__warning">{"> " + w.comment}</div>;
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
