import nodemailer from 'nodemailer';

// Apna SMTP config daalo (Gmail use kar rahe ho toh App Password chahiye)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'YOUR_EMAIL@gmail.com',
    pass: 'YOUR_APP_PASSWORD' // Normal password nahi, Gmail se App Password generate karo
  }
});

const leads = [
  { name: 'Alex', email: 'alex@inkbox.com' },
  { name: 'Dalton', email: 'dalton@wond.com' },
  // Yahan baaki 9 leads daal do
];

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function sendEmails() {
  for (const lead of leads) {
    const mailOptions = {
      from: 'YOUR_EMAIL@gmail.com',
      to: lead.email,
      subject: 'Pivoted to open-source (re: Semantic Gateway)',
      text: `Hey ${lead.name},\n\nYou ignored my last email about a hosted AI gateway. Makes sense—sending your agent's DB traffic to a third-party proxy is a massive security risk.\n\nI pivoted. I extracted the core AST firewall engine and open-sourced it as a local Express middleware (agent-sql-firewall). It runs 100% on your infrastructure (MIT licensed, zero data leaves your VPC) and blocks CTE-wrapped DROP TABLEs or unbounded DELETEs when your agents need write access.\n\nIf your agents write to Postgres, is it worth 2 minutes to drop this in your repo and see if it catches your edge cases?\n\nRepo: https://github.com/shreeghadge1212-boop/agent-sql-firewall`
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`Sent to ${lead.name} (${lead.email})`);
      
      // Spam se bachne ke liye 45 seconds ka delay
      await sleep(45000); 
    } catch (error) {
      console.error(`Error sending to ${lead.email}:`, error);
    }
  }
  console.log('All 11 emails dispatched.');
}

sendEmails();