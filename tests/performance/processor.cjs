module.exports = {
  generateUserData: (context, events, done) => {
    const id = Math.floor(Math.random() * 1000000);
    
    // Set variables in the context for use in the YAML
    context.vars.username = `user_${id}`;
    context.vars.email = `test_${id}@example.com`;
    context.vars.password = "TestPass123!"; // Hardcoded for consistency
    
    return done();
  }
};