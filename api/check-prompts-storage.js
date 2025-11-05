#!/usr/bin/env node
/**
 * Diagnostic script to check Azure Table Storage for Prompts
 * This helps debug the "Failed to fetch prompts" issue
 */

const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
require('dotenv').config();

async function checkPromptsStorage() {
  console.log('\n🔍 Azure Table Storage Diagnostic Tool\n');
  console.log('=' .repeat(60));

  // Step 1: Check environment variables
  console.log('\n1️⃣  Checking Environment Configuration...\n');

  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

  console.log(`   Storage Account: ${account ? '✅ ' + account : '❌ NOT SET'}`);
  console.log(`   Storage Key: ${accountKey ? '✅ ' + accountKey.substring(0, 10) + '...' : '❌ NOT SET'}`);
  console.log(`   Table Name: ${tableName}`);

  if (!account || !accountKey) {
    console.error('\n❌ ERROR: Azure Storage credentials not configured!');
    console.log('\nPlease set the following environment variables:');
    console.log('   - AZURE_STORAGE_ACCOUNT_NAME');
    console.log('   - AZURE_STORAGE_ACCOUNT_KEY');
    console.log('   - PROMPTS_TABLE_NAME (optional, defaults to "Prompts")');
    console.log('\nAdd them to your .env file or local.settings.json');
    process.exit(1);
  }

  // Step 2: Initialize Table Client
  console.log('\n2️⃣  Connecting to Azure Table Storage...\n');

  try {
    const credential = new AzureNamedKeyCredential(account, accountKey);
    const tableClient = new TableClient(
      `https://${account}.table.core.windows.net`,
      tableName,
      credential
    );

    console.log(`   ✅ Connected to table: ${tableName}`);

    // Step 3: Check if table exists
    console.log('\n3️⃣  Checking if table exists...\n');

    try {
      // Try to query the table - this will fail if table doesn't exist
      const testQuery = tableClient.listEntities({ queryOptions: { top: 1 } });
      await testQuery.next();
      console.log(`   ✅ Table "${tableName}" exists`);
    } catch (error) {
      if (error.statusCode === 404) {
        console.log(`   ⚠️  Table "${tableName}" does NOT exist`);
        console.log('\n   Creating table...');
        await tableClient.createTable();
        console.log(`   ✅ Table "${tableName}" created successfully`);
      } else {
        throw error;
      }
    }

    // Step 4: Count all entities
    console.log('\n4️⃣  Analyzing table contents...\n');

    let totalCount = 0;
    let promptCount = 0;
    let deletedCount = 0;
    const entities = [];

    const allEntities = tableClient.listEntities();

    for await (const entity of allEntities) {
      totalCount++;
      entities.push(entity);

      if (entity.partitionKey === 'PROMPT') {
        promptCount++;
        if (entity.isDeleted) {
          deletedCount++;
        }
      }
    }

    console.log(`   Total entities in table: ${totalCount}`);
    console.log(`   Entities with PartitionKey='PROMPT': ${promptCount}`);
    console.log(`   Active prompts (not deleted): ${promptCount - deletedCount}`);
    console.log(`   Deleted prompts: ${deletedCount}`);

    // Step 5: Show entity details
    if (entities.length === 0) {
      console.log('\n⚠️  No entities found in table!');
      console.log('\nThis explains why fetching prompts fails.');
      console.log('Try creating a prompt through the UI to populate the table.');
    } else {
      console.log('\n5️⃣  Entity Details:\n');

      entities.forEach((entity, index) => {
        console.log(`   Entity ${index + 1}:`);
        console.log(`      PartitionKey: ${entity.partitionKey}`);
        console.log(`      RowKey: ${entity.rowKey}`);
        console.log(`      Title: ${entity.title || 'N/A'}`);
        console.log(`      Category: ${entity.category || 'N/A'}`);
        console.log(`      IsDeleted: ${entity.isDeleted}`);
        console.log(`      Status: ${entity.status || 'N/A'}`);
        console.log(`      CreatedBy: ${entity.createdBy || 'N/A'}`);
        console.log(`      CreatedAt: ${entity.createdAt || 'N/A'}`);
        console.log('');
      });
    }

    // Step 6: Test the query filter used by the API
    console.log('\n6️⃣  Testing API query filter...\n');

    const filter = "PartitionKey eq 'PROMPT' and isDeleted eq false";
    console.log(`   Filter: ${filter}`);

    const filteredEntities = [];
    const queryResults = tableClient.listEntities({ queryOptions: { filter } });

    for await (const entity of queryResults) {
      filteredEntities.push(entity);
    }

    console.log(`   ✅ Query returned ${filteredEntities.length} entities`);

    if (filteredEntities.length > 0) {
      console.log('\n   Sample entity:');
      const sample = filteredEntities[0];
      console.log(`      ID: ${sample.rowKey}`);
      console.log(`      Title: ${sample.title}`);
      console.log(`      Category: ${sample.category}`);
      console.log(`      Tags: ${sample.tags}`);
    }

    // Step 7: Summary
    console.log('\n' + '='.repeat(60));
    console.log('\n📊 DIAGNOSTIC SUMMARY:\n');

    if (filteredEntities.length > 0) {
      console.log('   ✅ Storage is configured correctly');
      console.log('   ✅ Table exists and contains data');
      console.log(`   ✅ Found ${filteredEntities.length} active prompt(s)`);
      console.log('\n   The issue is likely on the frontend or API routing.');
      console.log('   Check the browser console for the exact error.');
    } else if (promptCount > 0) {
      console.log('   ⚠️  Prompts exist but are all marked as deleted');
      console.log('   The UI filters out deleted prompts.');
    } else if (totalCount > 0) {
      console.log('   ⚠️  Table contains data but no PROMPT entities');
      console.log('   Check the PartitionKey being used when creating prompts.');
    } else {
      console.log('   ⚠️  Table is empty - no data has been saved yet');
      console.log('   Try creating a prompt through the UI.');
    }

    console.log('\n' + '='.repeat(60) + '\n');

  } catch (error) {
    console.error('\n❌ ERROR:', error.message);
    console.error('\nFull error:', error);
    process.exit(1);
  }
}

// Run the diagnostic
checkPromptsStorage().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
