const express = require('express');
const _ = require('lodash');
const axios = require('axios');

const app = express();
app.use(express.json());

let items = [
  { id: 1, name: 'apple', price: 1.2 },
  { id: 2, name: 'banana', price: 0.5 },
];

app.get('/items', (req, res) => {
  res.json(items);
});

app.get('/items/:id', (req, res) => {
  const item = _.find(items, { id: Number(req.params.id) });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

app.post('/items', (req, res) => {
  // _.merge with user input is a real prototype-pollution sink on vulnerable lodash
  const newItem = _.merge({ id: items.length + 1 }, req.body);
  items.push(newItem);
  res.status(201).json(newItem);
});

app.get('/proxy', async (req, res) => {
  // axios here is the SSRF surface tied to the CVE
  try {
    const r = await axios.get(req.query.url);
    res.json({ status: r.status });
  } catch (e) {
    res.status(502).json({ error: 'fetch failed' });
  }
});

const PORT = process.env.PORT || 3000;

// Only start a listener when run directly, so tests can import `app` cleanly
if (require.main === module) {
  app.listen(PORT, () => console.log(`listening on ${PORT}`));
}

module.exports = app;