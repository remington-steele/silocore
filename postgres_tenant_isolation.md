Multi-tenant data isolation with PostgreSQL Row Level Security
by Michael Beardsley on 18 MAY 2020 in Amazon Aurora, Amazon RDS, PostgreSQL compatible, RDS for PostgreSQL Permalink  Comments 
Credit: https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/ 

Isolating tenant data is a fundamental responsibility for Software as a Service (SaaS) providers. If one of your tenants gains access to another tenant’s data, you lose trust and may permanently damage your brand or worse, lose your business.

With the risks so great, it is critical to have an effective data isolation plan. Multi-tenant architectures provide agility and operational cost savings by sharing data storage resources for all tenants instead of replicating those resources for each tenant. However, because it is difficult to enforce isolation in a shared model, you may compromise on your multi-tenant data model and revert to the costlier option of a database per tenant.

In a shared database model, often the only choice is to rely on your software developers to implement the proper checks with every SQL statement written. Just like other security concerns, you want to enforce tenant data isolation policies in a more centralized manner that is less dependent on the everyday variability of your source code.

This post, aimed at SaaS architects and developers, looks at a way to achieve both the benefits of a shared database for your tenants and centralized isolation enforcement.

# Data partitioning options
There are three common data partitioning models used in multi-tenant systems: silo, bridge, and pool. There are pros and cons of how each model enforces isolation.

## Silo – A separate database instance per tenant provides the most separation at the expense of both higher infrastructure costs and a more complicated tenant setup because you will have to create and manage a new database instance for each tenant that onboards to your SaaS offering.
Bridge – A second approach to partition tenant data is to share the same database instance but use a different schema for each tenant. The model can have cost savings due to resource sharing, but the maintenance and tenant setup can be quite complicated.
Pool – The third partitioning model uses both a shared database instance and namespace. In this design, all tenant data sits side-by-side, but each table or view contains a partitioning key (usually the tenant identifier), which you use to filter the data.
A pooled model saves the most on operational costs and reduces your infrastructure code and maintenance overhead. However, this model can be more difficult to enforce your data access policies, and is commonly implemented by hoping the correct WHERE clause is implemented in every SQL statement.

For more information about multi-tenant data partitioning, see the following AWS SaaS Factory whitepaper.

## Row Level Security
By centralizing the enforcement of RDBMS isolation policies at the database level you ease the burden on your software developers. This allows you to take advantage of the benefits of the pool model and reduce the risk of cross-tenant data access

PostgreSQL 9.5 and newer includes a feature called Row Level Security (RLS). When you define security policies on a table, these policies restrict which rows in that table are returned by SELECT queries or which rows are affected by INSERT, UPDATE, and DELETE commands. Amazon Relational Database Service (RDS) supports RLS with both Amazon Aurora for PostgreSQL and RDS for PostgreSQL engines. For more information, see Row Security Policies on the PostgreSQL website.

RLS policies have a name and are applied to and removed from a table with ALTER statements. The policies are defined with a USING clause that returns a Boolean value, which indicates whether to process a given row in the table. You can apply multiple policies to a table at the same time to enable complex security postures. Additionally, policies can cover all statement types (SELECT, INSERT, UPDATE, DELETE), or you can have different policies for modifications than for reads. If you use different policies for SELECT versus modifications, you must include the WITH CHECK clause in your policy definition.

You can think of an RLS policy as an automated WHERE clause that the database engine manages itself.

### Code examples
This post complements a full working example hosted in the AWS Samples section of GitHub. For more information, see the AWS SaaS Factory GitHub repo. The code examples in this post are taken from the repository and are not meant to be executed in isolation.

To create an RLS policy as part of your table definitions, see the following code:

-- Create a table for our tenants with indexes on the primary key and the tenant’s name
CREATE TABLE tenant (
    tenant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) UNIQUE,
    status VARCHAR(64) CHECK (status IN ('active', 'suspended', 'disabled')),
    tier VARCHAR(64) CHECK (tier IN ('gold', 'silver', 'bronze'))
);

-- Create a table for users of a tenant
CREATE TABLE tenant_user (
    user_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant (tenant_id) ON DELETE RESTRICT,
    email VARCHAR(255) NOT NULL UNIQUE,
    given_name VARCHAR(255) NOT NULL CHECK (given_name <> ''),
    family_name VARCHAR(255) NOT NULL CHECK (family_name <> '')
);

-- Turn on RLS
ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;

-- Restrict read and write actions so tenants can only see their rows
-- Cast the UUID value in tenant_id to match the type current_user returns
-- This policy implies a WITH CHECK that matches the USING clause
CREATE POLICY tenant_isolation_policy ON tenant
USING (tenant_id::TEXT = current_user);

-- And do the same for the tenant users
ALTER TABLE tenant_user ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_user_isolation_policy ON tenant_user
USING (tenant_id::TEXT = current_user);
Consider using numeric sequences for your primary key instead of random UUID values for better scalability and performance of large datasets. For more information, see UUID-OSSP on the PostgreSQL website.

## Using RLS
Given those table and policy definitions, assume there is a shared system level role (user) that you, the SaaS provider, use to provision the database and onboard new tenants. Here are some examples using the command line client for PostgreSQL, psql.

If you log in as the SaaS provider system level role that onboarded the tenants, you can see all your tenant records. This is because, by default, the table owner isn’t restricted by security policies unless the table is altered with FORCE ROW LEVEL SECURITY. See the following code:

rls_multi_tenant=> SELECT * FROM tenant;
              tenant_id               |    name  | status | tier 
--------------------------------------+----------+--------+------
 1cf1cc14-dd34-4a7b-b87d-adf79b2c255c | Tenant 1 | active | gold
 69ad9212-f5ef-456d-a724-dd8ea3c80d61 | Tenant 2 | active | gold
(2 rows)
And we can also see all of the tenant users.

rls_multi_tenant=> SELECT tenant_id, user_id, given_name || ' ' || family_name AS name FROM tenant_user;
              tenant_id               |               user_id                |      name       
--------------------------------------+--------------------------------------+-----------------
 1cf1cc14-dd34-4a7b-b87d-adf79b2c255c | d9f7d636-69a0-40d4-96d9-d429d1e1cee3 | User 1 Tenant 1
 69ad9212-f5ef-456d-a724-dd8ea3c80d61 | eb7a503a-a7c6-44c0-9916-8df68dd96815 | User 1 Tenant 2
(2 rows)
If you log in to the database as the non-system user Tenant 1 role, you can see the row level security policies in action. First, confirm that you are logged in as Tenant 1. See the following code:

rls_multi_tenant=> SELECT current_user;
             current_user             
--------------------------------------
 1cf1cc14-dd34-4a7b-b87d-adf79b2c255c
(1 row)
There is no error or messaging from the enforcement of the security policy for SELECT statements. Rows that don’t match the policy’s USING statement simply do not exist in the result set. See the following code:

rls_multi_tenant=> SELECT * FROM tenant;
              tenant_id               |    name  | status | tier 
--------------------------------------+----------+--------+------
 1cf1cc14-dd34-4a7b-b87d-adf79b2c255c | Tenant 1 | active | gold
(1 row)
Even if you try to brute force access to another tenant’s information, the policies protect you. See the following code:

rls_multi_tenant=> SELECT * FROM tenant WHERE tenant_id = '69ad9212-f5ef-456d-a724-dd8ea3c80d61'::UUID;
 tenant_id | name | status | tier 
-----------+------+--------+------
(0 rows)
UPDATE and DELETE statement policies are enforced similarly because the policy returns no matching rows to act on. See the following code:

rls_multi_tenant=> UPDATE tenant_user SET given_name = 'Cross Tenant Access' WHERE user_id = 'eb7a503a-a7c6-44c0-9916-8df68dd96815'::UUID;
UPDATE 0

rls_multi_tenant=> DELETE FROM tenant WHERE tenant_id = '69ad9212-f5ef-456d-a724-dd8ea3c80d61'::UUID;
DELETE 0
However, INSERT statements that fail a security policy return an error.

rls_multi_tenant=> INSERT INTO tenant (name) VALUES ('Tenant 3');
ERROR:  new row violates row-level security policy for table "tenant"
As Tenant 1, you can’t insert a new record because the value for the tenant_id column (auto- generated in this use case) doesn’t match your identity. If you specify your own identity ID while issuing an insert, a unique key violation is raised.

### Some considerations when using RLS
PostgreSQL super users and any role created with the BYPASSRLS attribute aren’t subject to table policies. Also, by default, the table owner bypasses RLS policies unless the table is altered with FORCE ROW LEVEL SECURITY. This is why the system level role that created the tenant and tenant_user tables can access all rows in the preceding examples.

If your application code connects to the database as the same PostgreSQL role as the table owner (usually the user that issued the CREATE TABLE statements unless later modified), your security policies aren’t in effect by default.

For this and other security and monitoring reasons, you should have your application connect to the database as a user other than the owner of the database objects.

The second item to address is how you define your USING clause. In the preceding examples, you used tenant_id = current_user, which means that the currently connected PostgreSQL role name must match the value in the tenant_id column for the row to be processed. If you use this mechanism, you need to create a PostgreSQL role for every tenant. This isn’t easy to maintain and doesn’t scale well.

## Alternative approach
If you don’t want to create and maintain PostgreSQL users for each of your tenants, you can still use a shared PostgreSQL login for your application. However, you need to define a runtime parameter to hold the current tenant context of your application. Make sure the login is not the table owner or defined with BYPASSRLS. This alternative, which is very scalable, looks similar to the following code:

CREATE POLICY tenant_isolation_policy ON tenant
USING (tenant_id = current_setting('app.current_tenant')::UUID);
Instead of comparing the currently logged-in PostgreSQL user to the tenant_id column, you use the built-in current_setting function to read the value of a configuration variable named app.current_tenant (and cast the text value to a UUID value because that’s the defined type of the tenant_id column). Your variable must be in the format of a prefix dot variable. Variables that don’t include a prefix are defined in the postgresql.conf file, which you don’t have access to in your RDS instance.

When you define the value of app.current_tenant, you can either use the built-in set_config function or the SQL command SET to declare a runtime parameter scoped to the current database connection session. This declaration should be made by your application code when you create the database connection or retrieve an existing one from your application connection pool. Because PostgreSQL scopes these variables to the current session, it’s safe to use them in a multi-connection application. Every connection has a separate copy of the variable and can’t access or modify any other connection’s runtime parameters.

Using session variables may be incompatible with server-side connection pooling such as pgBouncer. Be sure to review all implications of your connection pooling strategy and test if it shares session state.

### Example implementation
The following code example is one way to set the runtime parameter. Although this code uses the Java programming language, the mechanics are similar in your language of choice.

With Java Database Connectivity (JDBC), your code uses a javax.sql.DataSource instance and overrides the getConnection() method so that each time your application (or your connection pooling library) gets a connection to the database, the proper tenant context is set and the RLS policies on the tables enforce tenant isolation. It might look similar to the following code:

// Every time the app asks the data source for a connection
// set the PostgreSQL session variable to the current tenant
// to enforce data isolation.
@Override
public Connection getConnection() throws SQLException {
    Connection connection = super.getConnection();
    try (Statement sql = connection.createStatement()) {
        sql.execute("SET app.current_tenant = '" + TenantContext.getTenant() + "'");
    }
    return connection;
}
As with the command line psql client, the JDBC driver for PostgreSQL doesn’t treat triggering of RLS policies as an exception. If your query doesn’t fulfill the policy’s USING clause, it’s as if the rows don’t exist in the table and you get an empty result set.

This security protection at the database level means that every SQL statement your developers write will look the same, regardless of tenant context, and PostgreSQL enforces isolation for you. Your developers only have to write the correct WHERE clause for the business use case and don’t have to worry about operating in a shared, multi-tenant database.

Be sure to thoroughly test functions, procedures, views and complex nested queries to make sure there are no unintended restrictions or permissions due to your policy definitions.

# Conclusion
By taking advantage of PostgreSQL’s row level security feature, you can create SaaS applications that use a pool model to share database resources and also reduce the risk and overhead of enforcing your isolation polices. RLS lets you move the isolation enforcement to a centralized place in the PostgreSQL backend, away from your developer’s day-to-day coding.

The pool model helps avoid the higher costs of duplicated resources for each tenant and the specialized infrastructure code required to set up and maintain those copies. Because you have fewer resources and all your tenants are in one place, a single operational view of your platform is more straight forward to implement. This model can also simplify the database backup and restore process because you have fewer moving parts.

If you are currently using a silo or bridge model for your tenant data isolation, it might be time to look at RLS for a more agile and cost-effective approach.