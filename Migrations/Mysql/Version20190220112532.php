<?php
declare(strict_types=1);
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Migrations\AbortMigrationException;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

class Version20190220112532 extends AbstractMigration
{

    public function getDescription(): string
    {
        return 'Add "yeebase_twofactorauthentication_secret" table';
    }

    /**
     * @throws DBALException | AbortMigrationException
     */
    public function up(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('CREATE TABLE yeebase_twofactorauthentication_secret (accountidentifier VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, authenticationprovidername VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, secret VARCHAR(255) DEFAULT NULL COLLATE utf8_unicode_ci, timestamp INT DEFAULT NULL, UNIQUE INDEX unique_account (accountidentifier, authenticationprovidername)) DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE = InnoDB');
    }

    /**
     * @throws DBALException | AbortMigrationException
     */
    public function down(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('DROP TABLE yeebase_twofactorauthentication_secret');
    }
}
