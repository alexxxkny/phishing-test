import './App.css';
import { useEffect, useState } from 'react';
import Email from '../helpers/email';
import {PhishingCheck} from '../helpers/phishingCheck';
import EmailForm from '../components/EmailForm/EmailForm';

async function getNextLetter() {
  const result = await fetch('https://vir-lab.ru/');
  if (result.ok) {
    const email: Email = await result.json();
    return email;
  } else {
    console.error("Failed to get a letter");
  }
}

function App() {
  function processNextLetter() {
    getNextLetter()
    .then(email => {
      if (email) setPhishingCheck(new PhishingCheck(email));
    });
  }

  const [phishingCheck, setPhishingCheck]: [PhishingCheck | null, any] = useState(null);

  useEffect(() => {
    processNextLetter();
  }, []);

  return (
    <div className="App">
      <EmailForm
        phishingCheck={phishingCheck}
        onButtonClick={processNextLetter}
      />
    </div>
  );
}

export default App;
