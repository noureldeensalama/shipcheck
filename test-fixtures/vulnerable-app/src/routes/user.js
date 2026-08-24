app.get('/api/user/profile', (req, res) => {
  return res.json(db.getUser(req.query.id));
});
