const test = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const app = require('../index');

test('GET /items returns an array', async () => {
  const res = await request(app).get('/items');
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(res.body));
});

test('GET /items/:id returns the right item', async () => {
  const res = await request(app).get('/items/1');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.name, 'apple');
});

test('POST /items creates an item', async () => {
  const res = await request(app).post('/items').send({ name: 'cherry', price: 3 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.name, 'cherry');
});