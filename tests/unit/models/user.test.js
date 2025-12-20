import { sequelize, User, Role, RefreshToken, UserRole } from '../../../src/models/index.js'; // Ensure this points to your central models file
import bcrypt from 'bcrypt';

describe('User Model (SQLite)', () => {
  
  // 1. Run once before all tests in this file
  beforeAll(async () => {
    
    try {
      // Authenticate connection and sync the database schema
      await sequelize.authenticate();
      await sequelize.sync({ force: true }); 
      // Postgres enforces FKs by default, so no PRAGMA needed
    } catch (error) {
      console.error('Unable to connect to the database or sync schema:', error);
      throw error; 
    }
  });

  // 2. Clean up data between tests to ensure isolation
  afterEach(async () => {
    // Delete in order of dependencies (Child tables first)
    // This prevents Foreign Key constraint errors during cleanup
    await RefreshToken.destroy({ where: {}, truncate: false });
    await UserRole.destroy({ where: {}, truncate: false });
    await User.destroy({ where: {}, truncate: false });
    await Role.destroy({ where: {}, truncate: false });
  });

  // 3. Close connection after all tests are done
  afterAll(async () => {
    await sequelize.close();
  });

  it('creates user with hashed password', async () => {
    const userData = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'Password123!',
    };

    const user = await User.create(userData);
    
    expect(user.username).toBe(userData.username);
    expect(user.passwordHash).not.toBe(userData.password);
    
    const isMatch = await bcrypt.compare(userData.password, user.passwordHash);
    expect(isMatch).toBe(true);
  });

  it('toJSON excludes passwordHash', async () => {
    const user = await User.create({
      username: 'cleanuser',
      email: 'clean@example.com',
      password: 'Password123!',
    });

    const userJson = user.toJSON();
    expect(userJson.passwordHash).toBeUndefined();
    expect(userJson.username).toBe('cleanuser');
  });

  it('associates with roles', async () => {
    const user = await User.create({
      username: 'roleuser',
      email: 'role@example.com',
      password: 'Password123!',
    });

    const role = await Role.create({ name: 'admin' });
    await user.addRole(role);

    const userWithRoles = await User.findByPk(user.id, {
      include: [{ model: Role, as: 'roles' }]
    });

    expect(userWithRoles.roles).toHaveLength(1);
    expect(userWithRoles.roles[0].name).toBe('admin');
  });
});