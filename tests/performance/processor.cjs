module.exports = {
  generateUserData: (context, events, done) => {
    // Combine timestamp with a shorter random number
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 1000);
    const uniqueId = `${timestamp}${random}`;
    
    // Set variables in the context for use in the YAML
    context.vars.username = `user_${uniqueId}`;
    context.vars.email = `test_${uniqueId}@example.com`;
    context.vars.password = "TestPass123!"; // Hardcoded for consistency
    
    return done();
  }
};