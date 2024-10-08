SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE table  test.users;
SET FOREIGN_KEY_CHECKS = 1;
TRUNCATE TABLE authorities;

/*set sql_require_primary_key = off;
create table users(username varchar(191) COLLATE utf8mb4_general_ci
                       not null primary key,password varchar(191) COLLATE utf8mb4_general_ci
                       not null,enabled boolean not null);
create table authorities (username varchar(50) COLLATE utf8mb4_general_ci
                              not null,authority varchar(50) COLLATE utf8mb4_general_ci null,constraint
                              fk_authorities_users foreign key(username) references users(username));
create unique index ix_auth_username on authorities (username,authority);
*/
