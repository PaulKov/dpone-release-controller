/** Exact direct capabilities of reviewed verifier/data transforms (A). */
export const REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_A = Object.freeze({
  "provider-quarantine-ast-capabilities.mjs#assertAstProductionModules": Object.freeze([]),
  "provider-quarantine-ast-capabilities.mjs#collectTopLevelFunctionNodes": caps(
    "injected-call:caller.values|injected-reference:program",
  ),
  "bootstrap-live-workers.mjs#<module>": caps("native-entry-dispatch:process.argv[1]"),
  "check-module-size.mjs#<module>": caps(
    "ambient-call:ambient:process.stderr.write|ambient-call:ambient:process.stdout.write|ambient-reference:ambient:process.argv.?|ambient-reference:ambient:process.exitCode|intrinsic-reference:intrinsic:Error|native-entry-dispatch:process.argv[1]",
  ),
  "check-module-size.mjs#asciiCompare": caps("injected-reference:left|injected-reference:right"),
  "check-module-size.mjs#assessModules": caps(
    "injected-call:caller.filter|injected-call:caller.map|injected-call:caller.sort|injected-reference:limits|injected-reference:limits.nonblank|injected-reference:limits.physical|injected-reference:modules",
  ),
  "check-module-size.mjs#countSourceLines": caps(
    "injected-call:caller.split|injected-call:lines.at|injected-call:lines.pop|injected-call:lines.reduce|injected-call:source.replace|injected-reference:lines.length|injected-reference:source",
  ),
  "check-module-size.mjs#displayPath": caps(
    "injected-call:caller.join|injected-call:caller.split|injected-reference:absolutePath|injected-reference:projectRoot",
  ),
  "check-module-size.mjs#formatViolations": caps(
    "injected-call:caller.join|injected-call:violations.map|injected-reference:limits|injected-reference:limits.nonblank|injected-reference:limits.physical|injected-reference:rows|injected-reference:rows.length",
  ),
  "check-module-size.mjs#isWithin": caps(
    "injected-call:path.startsWith|injected-reference:child|injected-reference:parent|injected-reference:path",
  ),
  "check-module-size.mjs#runModuleSizeGate": caps(
    "injected-reference:modules|injected-reference:modules.length|injected-reference:projectRoot|injected-reference:violations|injected-reference:violations.length",
  ),
  "check-module-size.mjs#scanModules": caps(
    "injected-call:caller.sort|injected-reference:absoluteProjectRoot|injected-reference:absoluteRoot|injected-reference:projectRoot|injected-reference:root|injected-reference:roots",
  ),
  "check-module-size.mjs#visit": caps(
    "filesystem-read:lstat|filesystem-read:readFile|filesystem-read:readdir|injected-call:directoryStat.isDirectory|injected-call:directoryStat.isSymbolicLink|injected-call:entries.sort|injected-call:modules.push|injected-call:name.endsWith|injected-call:seen.add|injected-call:seen.has|injected-call:stat.isDirectory|injected-call:stat.isFile|injected-call:stat.isSymbolicLink|injected-reference:absolutePath|injected-reference:bytes|injected-reference:directory|injected-reference:entries|injected-reference:modules|injected-reference:name|injected-reference:path|injected-reference:projectRoot|injected-reference:seen|injected-reference:source",
  ),
  "check-publication-privacy.mjs#<module>": caps(
    "ambient-call:ambient:process.stderr.write|ambient-call:ambient:process.stdout.write|ambient-reference:ambient:process.exitCode|intrinsic-reference:intrinsic:Error|native-entry-dispatch:process.argv[1]",
  ),
  "check-publication-privacy.mjs#asciiCompare": caps(
    "injected-reference:left|injected-reference:right",
  ),
  "check-publication-privacy.mjs#listRegularFiles": caps("injected-reference:root"),
  "check-publication-privacy.mjs#runPublicationPrivacyGate": caps(
    "filesystem-read:readFileSync|filesystem-read:readdirSync|injected-call:caller.filter|injected-call:caller.join|injected-call:caller.sort|injected-call:caller.split|injected-call:displayPath.startsWith|injected-reference:actualTemplates|injected-reference:displayPath|injected-reference:files|injected-reference:files.length|injected-reference:path|injected-reference:projectRoot|injected-reference:source",
  ),
  "check-publication-privacy.mjs#visit": caps(
    "filesystem-read:lstatSync|filesystem-read:readdirSync|injected-call:caller.sort|injected-call:files.push|injected-call:stat.isDirectory|injected-call:stat.isFile|injected-call:stat.isSymbolicLink|injected-reference:directory|injected-reference:files|injected-reference:name|injected-reference:path|injected-reference:root",
  ),
  "closed-module-inventory.mjs#asciiCompare": caps(
    "injected-reference:left|injected-reference:right",
  ),
  "closed-module-inventory.mjs#assertClosedModuleInventory": caps(
    "intrinsic-reference:intrinsic:Map",
  ),
  "closed-module-inventory.mjs#relativeModuleImports": caps(
    "injected-call:source.matchAll|injected-reference:match.?",
  ),
  "closed-module-inventory.mjs#sortedUnique": caps(
    "injected-call:caller.sort|injected-call:values.some|injected-reference:caller.size|injected-reference:name|injected-reference:sorted|injected-reference:sorted.length|injected-reference:values",
  ),
  "deploy-version.mjs#<module>": caps("native-entry-dispatch:process.argv[1]"),
  "generate-runtime-closure-schema.mjs#<module>": caps(
    "ambient-call:ambient:process.stdout.write|ambient-computed-reference:ambient:process.argv|ambient-reference:ambient:process.argv.?|ambient-reference:ambient:process.argv.length",
  ),
  "generate-runtime-closure-schema.mjs#canonical": caps(
    "injected-call:caller.join|injected-call:caller.map|injected-call:caller.sort|injected-call:value.map|injected-reference:value|injected-reference:value.?",
  ),
  "generate-runtime-closure-schema.mjs#constant": caps("injected-reference:value"),
  "generate-runtime-closure-schema.mjs#integer": caps(
    "injected-reference:maximum|injected-reference:minimum",
  ),
  "generate-runtime-closure-schema.mjs#object": caps(
    "injected-call:caller.sort|injected-reference:properties",
  ),
  "generate-runtime-closure-schema.mjs#string": caps("injected-reference:pattern"),
  "live-worker-config.mjs#liveWorkerDefinition": caps("injected-reference:filename"),
  "live-worker-config.mjs#loadLiveWorkerConfig": caps(
    "filesystem-read:readFileSync|injected-reference:config|injected-reference:definition|injected-reference:definition.name|injected-reference:filename|injected-reference:path|injected-reference:resolved",
  ),
  "live-worker-config.mjs#requireB2Bucket": caps("injected-reference:vars"),
  "live-worker-config.mjs#requireExactKeys": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:expected|injected-reference:name|injected-reference:sortedExpected|injected-reference:value",
  ),
  "live-worker-config.mjs#requireLiteral": caps(
    "injected-reference:expected|injected-reference:key|injected-reference:object.?",
  ),
  "live-worker-config.mjs#requirePattern": caps(
    "injected-call:pattern.test|injected-reference:key|injected-reference:object.?|injected-reference:pattern.lastIndex|injected-reference:value",
  ),
  "live-worker-config.mjs#requireProviderIds": caps(
    "injected-reference:vars|injected-reference:vars.GITHUB_APP_ID|injected-reference:vars.GITHUB_APP_INSTALLATION_ID",
  ),
  "live-worker-config.mjs#requireRecord": caps(
    "injected-reference:name|injected-reference:value|intrinsic-prototype-reference:intrinsic:Object",
  ),
  "live-worker-config.mjs#validateDurableObjects": caps(
    "injected-call:bindings.forEach|injected-reference:bindings|injected-reference:bindings.length|injected-reference:durable|injected-reference:durable.bindings|injected-reference:migrations|injected-reference:value",
  ),
  "live-worker-config.mjs#validateIngress": caps(
    "injected-reference:config.?|injected-reference:config.custom_domain|injected-reference:config.durable_objects|injected-reference:config.length|injected-reference:config.migrations|injected-reference:config.pattern|injected-reference:config.routes|injected-reference:config.services|injected-reference:config.vars|injected-reference:vars",
  ),
  "live-worker-config.mjs#validateLiveWorkerConfig": caps(
    "injected-reference:config|injected-reference:config.$schema|injected-reference:config.account_id|injected-reference:config.compatibility_date|injected-reference:config.durable_objects|injected-reference:config.main|injected-reference:config.migrations|injected-reference:config.name|injected-reference:config.observability|injected-reference:config.preview_urls|injected-reference:config.services|injected-reference:config.vars|injected-reference:config.version_metadata|injected-reference:config.workers_dev|injected-reference:definition|injected-reference:definition.kind|injected-reference:definition.main|injected-reference:definition.name|injected-reference:expectedName|injected-reference:extras|injected-reference:filename",
  ),
  "live-worker-config.mjs#validateServiceBindings": caps(
    "injected-call:value.forEach|injected-reference:expected.?|injected-reference:expected.length|injected-reference:value|injected-reference:value.length",
  ),
  "live-worker-config.mjs#validateVariables": caps(
    "injected-reference:accountId|injected-reference:definition.kind|injected-reference:definition.name|injected-reference:expected|injected-reference:key|injected-reference:value|injected-reference:vars|injected-reference:vars.?",
  ),
  "live-worker-config.mjs#validateWormDurableObjects": caps(
    "injected-reference:durable|injected-reference:durable.bindings|injected-reference:migrations|injected-reference:value",
  ),
  "provider-mutation-hold.mjs#assertProviderMutationReleased": caps(
    "injected-reference:classified|injected-reference:entrypoint|injected-reference:error|injected-reference:error.code|injected-reference:error.entrypoint|injected-reference:error.marker|injected-reference:label",
  ),
  "provider-mutation-hold.mjs#boundary": caps(
    "injected-reference:entrypoint|injected-reference:module|injected-reference:symbol",
  ),
  "provider-quarantine-ast-boundaries.mjs#assertAstProviderBoundaries": caps(
    "injected-call:boundaries.map|injected-call:caller.sort|injected-call:sources.get|injected-reference:actualEntrypoints|injected-reference:boundaries|injected-reference:boundary|injected-reference:boundaryByKey|injected-reference:caller.size|injected-reference:effectExports|injected-reference:entrypoints|injected-reference:expected|injected-reference:filename|injected-reference:keys|injected-reference:keys.length|injected-reference:program",
  ),
  "provider-quarantine-ast-boundaries.mjs#assertBoundary": caps(
    "injected-call:declaration.some|injected-call:effectExports.includes|injected-call:programs.get|injected-reference:boundary|injected-reference:boundaryByKey|injected-reference:declaration|injected-reference:declaration.?|injected-reference:entrypoint|injected-reference:first|injected-reference:module|injected-reference:program|injected-reference:symbol",
  ),
  "provider-quarantine-ast-boundaries.mjs#assertGuardedReexport": caps(
    "injected-call:boundaryByKey.get|injected-reference:boundary.entrypoint|injected-reference:boundary.module|injected-reference:boundary.symbol|injected-reference:program.body|injected-reference:resolved.entrypoint|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.source|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value",
  ),
  "provider-quarantine-ast-boundaries.mjs#assertHoldImplementation": caps(
    "injected-call:caller.some|injected-call:declaration.at|injected-reference:declaration|injected-reference:declaration.async|injected-reference:declaration.generator|injected-reference:declaration.length|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:finalStatement.name|injected-reference:finalStatement.type|injected-reference:node.source|injected-reference:node.type|injected-reference:program|injected-reference:source",
  ),
  "provider-quarantine-ast-boundaries.mjs#assertNoLocalCallableExportAliases": caps(
    "injected-call:callableNames.has|injected-reference:declaration.declarations|injected-reference:declaration.type|injected-reference:declarator.init|injected-reference:declarator.name|injected-reference:declarator.type|injected-reference:filename|injected-reference:program|injected-reference:program.body|injected-reference:statement.declaration|injected-reference:statement.length|injected-reference:statement.source|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-boundaries.mjs#astDigest": caps(
    "injected-call:caller.digest|injected-reference:canonical|injected-reference:node",
  ),
  "provider-quarantine-ast-boundaries.mjs#effectCallableKeys": caps(
    "injected-call:dataKeys.has|injected-reference:filename|injected-reference:program|injected-reference:programs|injected-reference:symbol",
  ),
  "provider-quarantine-ast-boundaries.mjs#exactReexportTarget": caps(
    "injected-call:programs.has|injected-call:source.slice|injected-reference:filename|injected-reference:source",
  ),
  "provider-quarantine-ast-boundaries.mjs#exportedSymbols": caps(
    "injected-reference:declaration.declarations|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:item.name|injected-reference:item.type|injected-reference:program.body|injected-reference:specifier.name|injected-reference:statement.declaration|injected-reference:statement.specifiers|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-boundaries.mjs#isCallableExpression": caps(
    "injected-reference:node.type",
  ),
  "provider-quarantine-ast-boundaries.mjs#isExactHoldStatement": caps(
    "injected-reference:call.length|injected-reference:call.name|injected-reference:call.optional|injected-reference:call.type|injected-reference:call.value|injected-reference:entrypoint|injected-reference:statement.expression|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-boundaries.mjs#resolvesToCallableExport": caps(
    "injected-call:declaration.find|injected-call:programs.get|injected-call:seen.add|injected-call:seen.has|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:declarator|injected-reference:declarator.init|injected-reference:filename|injected-reference:key|injected-reference:program.body|injected-reference:programs|injected-reference:seen|injected-reference:specifier.name|injected-reference:statement.declaration|injected-reference:statement.source|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value|injected-reference:symbol|injected-reference:target",
  ),
  "provider-quarantine-ast-boundaries.mjs#topLevelCallableNames": caps(
    "injected-reference:declaration.declarations|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:item.init|injected-reference:item.name|injected-reference:item.type|injected-reference:program.body|injected-reference:statement|injected-reference:statement.declaration|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-capabilities.mjs#addFunction": caps(
    "injected-call:functions.has|injected-call:functions.set|injected-reference:declaration|injected-reference:filename|injected-reference:name",
  ),
  "provider-quarantine-ast-capabilities.mjs#assertExactKeys": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:actualIterable|injected-reference:expected|injected-reference:expectedIterable|injected-reference:label",
  ),
  "provider-quarantine-ast-capabilities.mjs#assertRelativeExportExists": caps(
    "injected-call:expectedExports.includes|injected-reference:expectedExports|injected-reference:filename|injected-reference:imported|injected-reference:source|injected-reference:target",
  ),
  "provider-quarantine-ast-capabilities.mjs#assertStaticProductionImports": caps(
    "injected-call:nodes.filter|injected-call:statement.some|injected-call:statement.startsWith|injected-reference:dynamicImports.?|injected-reference:dynamicImports.length|injected-reference:expectedExports|injected-reference:filename|injected-reference:node.name|injected-reference:node.type|injected-reference:nodes|injected-reference:program|injected-reference:program.body|injected-reference:statement.source|injected-reference:statement.type|injected-reference:statement.value",
  ),
  "provider-quarantine-ast-capabilities.mjs#buildModule": caps(
    "injected-call:functions.values|injected-call:nodes.set|injected-reference:declaration|injected-reference:expectedExports|injected-reference:filename|injected-reference:functions|injected-reference:imports|injected-reference:key|injected-reference:lexicalReferences|injected-reference:localCapabilityOwnerDigests.?|injected-reference:localCapabilityOwners|injected-reference:moduleDigest|injected-reference:moduleKey|injected-reference:name|injected-reference:nodes|injected-reference:program|injected-reference:reviewedDigest",
  ),
  "provider-quarantine-ast-capabilities.mjs#collectDirectExportedFunctionKeys": caps(
    "injected-call:functions.has|injected-reference:filename|injected-reference:program|injected-reference:symbol",
  ),
  "provider-quarantine-ast-capabilities.mjs#collectExportAliases": caps(
    "injected-call:functions.has|injected-call:imported.startsWith|injected-call:imports.get|injected-call:statement.startsWith|injected-reference:alias|injected-reference:expectedExports|injected-reference:filename|injected-reference:imported.imported|injected-reference:imported.source|injected-reference:program.body|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.declaration|injected-reference:statement.source|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value|injected-reference:target|injected-reference:targetFilename",
  ),
  "provider-quarantine-ast-capabilities.mjs#collectImportBindings": caps(
    "injected-call:statement.startsWith|injected-reference:expectedExports|injected-reference:filename|injected-reference:imported|injected-reference:program.body|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value",
  ),
  "provider-quarantine-ast-capabilities.mjs#collectTopLevelFunctions": caps(
    "injected-reference:declaration|injected-reference:declaration.declarations|injected-reference:declaration.id|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:filename|injected-reference:item.init|injected-reference:item.name|injected-reference:item.type|injected-reference:program.body|injected-reference:statement|injected-reference:statement.declaration|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-capabilities.mjs#exactRelativeTarget": caps(
    "injected-call:source.slice|injected-reference:expectedExports|injected-reference:filename|injected-reference:source|injected-reference:target",
  ),
  "provider-quarantine-ast-capabilities.mjs#isExactTrustedBootstrapImport": caps(
    "injected-reference:filename|injected-reference:node.type|injected-reference:node.value",
  ),
  "provider-quarantine-ast-classifier.mjs#classifyCapabilityCall": caps(
    "injected-call:caller.some|injected-call:flow.callerRoot|injected-call:flow.origins|injected-call:imports.get|injected-call:intrinsic.slice|injected-call:objectOrigins.has|injected-call:origins.has|injected-reference:ambient|injected-reference:call.callee|injected-reference:callee|injected-reference:callee.computed|injected-reference:callee.name|injected-reference:callee.object|injected-reference:callee.type|injected-reference:caller|injected-reference:imported|injected-reference:intrinsic|injected-reference:namespace.imported|injected-reference:namespace.source|injected-reference:objectOrigins|injected-reference:origins|injected-reference:property|injected-reference:root",
  ),
  "provider-quarantine-ast-classifier.mjs#classifyCapabilityReference": caps(
    "injected-call:caller.some|injected-call:flow.callerRoot|injected-call:flow.origins|injected-call:importedRoot.startsWith|injected-call:imports.get|injected-call:objectOrigins.has|injected-call:origins.has|injected-reference:ambient|injected-reference:caller|injected-reference:capability|injected-reference:computedRoot|injected-reference:imported|injected-reference:intrinsic|injected-reference:namespace.imported|injected-reference:namespace.source|injected-reference:node|injected-reference:node.computed|injected-reference:node.name|injected-reference:node.object|injected-reference:node.type|injected-reference:node.value|injected-reference:objectOrigins|injected-reference:origins|injected-reference:parent|injected-reference:parent.callee|injected-reference:parent.object|injected-reference:parent.type|injected-reference:property|injected-reference:root",
  ),
  "provider-quarantine-ast-classifier.mjs#classifyConstructor": caps(
    "injected-call:caller.some|injected-call:flow.origins|injected-call:origins.has|injected-reference:ambient|injected-reference:callee|injected-reference:callee.name|injected-reference:callee.type|injected-reference:expression.callee|injected-reference:intrinsic|injected-reference:origins",
  ),
  "provider-quarantine-ast-classifier.mjs#resolveCalledFunction": caps(
    "injected-call:functions.has|injected-call:imported.slice|injected-call:imported.startsWith|injected-call:imports.get|injected-call:key.split|injected-reference:callee.name|injected-reference:callee.type|injected-reference:calleeNode|injected-reference:caller.?|injected-reference:expectedExports|injected-reference:filename|injected-reference:imported|injected-reference:imported.imported",
  ),
  "provider-quarantine-ast-classifier.mjs#resolveReferencedFunction": caps(
    "injected-call:functions.has|injected-call:imported.slice|injected-call:imported.startsWith|injected-call:imports.get|injected-call:key.split|injected-reference:caller.?|injected-reference:expectedExports|injected-reference:filename|injected-reference:imported|injected-reference:imported.imported|injected-reference:node|injected-reference:node.name|injected-reference:node.type|injected-reference:parent|injected-reference:parent.callee|injected-reference:parent.type",
  ),
  "provider-quarantine-ast-core.mjs#asciiCompare": caps(
    "injected-reference:left|injected-reference:right",
  ),
  "provider-quarantine-ast-core.mjs#assertExactModuleExports": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:expected|injected-reference:filename|injected-reference:program",
  ),
  "provider-quarantine-ast-core.mjs#assertUnshadowedNamedImport": caps(
    "injected-reference:imported|injected-reference:local|injected-reference:matched|injected-reference:node|injected-reference:node.argument|injected-reference:node.left|injected-reference:node.type|injected-reference:program|injected-reference:program.body|injected-reference:source|injected-reference:specifier|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value",
  ),
  "provider-quarantine-ast-core.mjs#astNodes": caps("injected-reference:root"),
  "provider-quarantine-ast-core.mjs#bindingContains": caps(
    "injected-call:pattern.some|injected-reference:name|injected-reference:pattern|injected-reference:pattern.argument|injected-reference:pattern.left|injected-reference:pattern.name|injected-reference:pattern.type|injected-reference:pattern.value",
  ),
  "provider-quarantine-ast-core.mjs#canonicalImportDigest": caps(
    "injected-call:caller.digest|injected-reference:filename|injected-reference:program",
  ),
  "provider-quarantine-ast-core.mjs#canonicalImportInventory": caps(
    "injected-call:caller.sort|injected-call:statement.map|injected-reference:filename|injected-reference:program.body|injected-reference:statement.length|injected-reference:statement.source|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-core.mjs#collectDeclarationExports": caps(
    "injected-call:exports.push|injected-reference:declaration.declarations|injected-reference:declaration.generator|injected-reference:declaration.id|injected-reference:declaration.kind|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:filename|injected-reference:item.name|injected-reference:item.type",
  ),
  "provider-quarantine-ast-core.mjs#collectModuleExports": caps(
    "injected-reference:filename|injected-reference:program.body|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.declaration|injected-reference:statement.exportKind|injected-reference:statement.specifiers|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-core.mjs#declaresBinding": caps(
    "injected-call:node.some|injected-reference:name|injected-reference:node.id|injected-reference:node.name|injected-reference:node.param|injected-reference:node.type",
  ),
  "provider-quarantine-ast-core.mjs#exactModuleSource": caps(
    "injected-reference:filename|injected-reference:source.type|injected-reference:source.value",
  ),
  "provider-quarantine-ast-core.mjs#exportBinding": caps(
    "injected-reference:specifier.name|injected-reference:specifier.type",
  ),
  "provider-quarantine-ast-core.mjs#findDirectExportedFunction": caps(
    "injected-reference:declaration|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:program.body|injected-reference:statement.declaration|injected-reference:statement.type|injected-reference:symbol",
  ),
  "provider-quarantine-ast-core.mjs#findNamedReexport": caps(
    "injected-call:program.some|injected-reference:source|injected-reference:symbol",
  ),
  "provider-quarantine-ast-core.mjs#importBinding": caps(
    "injected-reference:specifier.name|injected-reference:specifier.type",
  ),
  "provider-quarantine-ast-core.mjs#parseQuarantineModule": caps(
    "injected-reference:filename|injected-reference:source|intrinsic-reference:intrinsic:Error",
  ),
  "provider-quarantine-ast-effects.mjs#firstOrigin": caps(
    "injected-call:caller.find|injected-reference:origins|injected-reference:prefix",
  ),
  "provider-quarantine-ast-effects.mjs#addMembers": caps(
    "injected-call:members.add|injected-reference:node|injected-reference:node.type|injected-reference:root",
  ),
  "provider-quarantine-ast-effects.mjs#assertEffectModuleScope": caps(
    "injected-call:reviewedMembers.has|injected-reference:filename|injected-reference:node|injected-reference:node.operator|injected-reference:node.type|injected-reference:program|injected-reference:skipped",
  ),
  "provider-quarantine-ast-effects.mjs#isExactCall": caps(
    "injected-call:argumentCheck|injected-reference:name|injected-reference:node.?|injected-reference:node.length|injected-reference:node.name|injected-reference:node.optional|injected-reference:node.type",
  ),
  "provider-quarantine-ast-effects.mjs#isImportMetaUrl": caps(
    "injected-reference:node.computed|injected-reference:node.name|injected-reference:node.type",
  ),
  "provider-quarantine-ast-effects.mjs#isNativeEntryStatement": caps(
    "injected-reference:expression|injected-reference:expression.argument|injected-reference:expression.type|injected-reference:invocation.length|injected-reference:invocation.name|injected-reference:invocation.optional|injected-reference:invocation.type|injected-reference:statement.alternate|injected-reference:statement.expression|injected-reference:statement.length|injected-reference:statement.test|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-effects.mjs#isNativeEntryTest": caps(
    "injected-reference:test.left|injected-reference:test.name|injected-reference:test.operator|injected-reference:test.right|injected-reference:test.type",
  ),
  "provider-quarantine-ast-effects.mjs#isProcessArgvOne": caps(
    "injected-reference:node.computed|injected-reference:node.name|injected-reference:node.type|injected-reference:node.value",
  ),
  "provider-quarantine-ast-effects.mjs#reviewedModuleMembers": caps(
    "injected-reference:declaration.declarations|injected-reference:declaration.type|injected-reference:item.init|injected-reference:program.body|injected-reference:statement|injected-reference:statement.declaration|injected-reference:statement.test|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-effects.mjs#isReviewedLocalCapability": caps(
    "injected-call:capability.startsWith|injected-reference:capability",
  ),
  "provider-quarantine-ast-effects.mjs#wordSet": caps("injected-call:source.split"),
  "provider-quarantine-ast-graph.mjs#combineGraphs": caps(
    "injected-call:modules.values|injected-reference:key|injected-reference:module.nodes|injected-reference:value",
  ),
  "provider-quarantine-ast-graph.mjs#materializeCallableExportAliases": caps(
    "injected-call:caller.add|injected-call:graph.set|injected-call:modules.get|injected-call:modules.values|injected-reference:alias|injected-reference:graph|injected-reference:module.exportAliases|injected-reference:target",
  ),
});

function caps(value) {
  return Object.freeze(value.split("|"));
}
