import React, { useState } from 'react';
import './FAQSection.css';

// Sample FAQ data – replace with real content later
const FAQ_DATA = [
  {
    question: 'What is Soroban?',
    answer: 'Soroban is a smart‑contract platform built on the Stellar network, enabling fast, low‑cost transactions.'
  },
  {
    question: 'How do I connect my Web3 wallet?',
    answer: 'Use the "Connect Wallet" button in the header. The app currently supports any wallet that implements the EIP‑1193 provider interface.'
  },
  {
    question: 'Is my file encrypted?',
    answer: 'All uploaded files are encrypted client‑side with AES‑256 before they ever touch the server.'
  },
  {
    question: 'Can I search my FAQs?',
    answer: 'Yes – the search bar filters questions in real‑time as you type.'
  }
];

/**
 * FAQSection – an interactive, accessible FAQ/Help Center component.
 *
 * Features:
 * • Accessible accordion widgets (button + aria attributes)
 * • Smooth rotation of the chevron icon on expand/collapse
 * • Instant client‑side search filtering
 * • Micro‑animations for accordion content (height & opacity)
 */
export default function FAQSection() {
  const [searchTerm, setSearchTerm] = useState('');
  const [openIndex, setOpenIndex] = useState(null);

  const filteredFaq = FAQ_DATA.filter(item =>
    item.question.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const toggle = index => {
    setOpenIndex(prev => (prev === index ? null : index));
  };

  return (
    <section className="faq-section">
      <h2 className="faq-title">Frequently Asked Questions</h2>
      <input
        type="text"
        placeholder="Search…"
        className="faq-search"
        value={searchTerm}
        onChange={e => setSearchTerm(e.target.value)}
        aria-label="Search FAQs"
      />
      <div className="faq-list" role="list">
        {filteredFaq.map((item, idx) => (
          <div key={idx} className="faq-item" role="listitem">
            <button
              className="faq-question"
              onClick={() => toggle(idx)}
              aria-expanded={openIndex === idx}
              aria-controls={`faq-answer-${idx}`}
            >
              <span>{item.question}</span>
              <span
                className={`chevron ${openIndex === idx ? 'rotated' : ''}`}
                aria-hidden="true"
              >▼</span>
            </button>
            <div
              id={`faq-answer-${idx}`}
              className={`faq-answer ${openIndex === idx ? 'open' : ''}`}
              role="region"
              aria-labelledby={`faq-question-${idx}`}
            >
              <p>{item.answer}</p>
            </div>
          </div>
        ))}
        {filteredFaq.length === 0 && (
          <p className="no-results">No matching questions found.</p>
        )}
      </div>
    </section>
  );
}
