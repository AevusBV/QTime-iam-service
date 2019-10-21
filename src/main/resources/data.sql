INSERT INTO ROLE (ID, NAME) VALUES
(1, 'ROLE_ADMIN'),
(2, 'ROLE_EMPLOYEE'),
(3, 'ROLE_MANAGER'),
(4, 'ROLE_ASSISTANT_MANAGER');

INSERT  INTO QUSER (ID, USERNAME, PASSWORD, FIRST_NAME, LAST_NAME) VALUES
(1, 'admin', '$2a$04$S5N37xGGTNota0uS5rW8huaLI3LmL5IKhtpwzMLecQ9XBKBv2ND/e', 'John', 'Doe'),
(2, 'employee', '$2a$04$S5N37xGGTNota0uS5rW8huaLI3LmL5IKhtpwzMLecQ9XBKBv2ND/e', 'John', 'Doe'),
(3, 'manager', '$2a$04$S5N37xGGTNota0uS5rW8huaLI3LmL5IKhtpwzMLecQ9XBKBv2ND/e', 'John', 'Doe'),
(4, 'assistantManager', '$2a$04$S5N37xGGTNota0uS5rW8huaLI3LmL5IKhtpwzMLecQ9XBKBv2ND/e', 'John', 'Doe');

INSERT INTO QUSER_ROLES (QUSER_ID, ROLES_ID) VALUES
(1, 1),
(2, 2),
(3, 2),
(3, 3),
(4, 2),
(4, 4);