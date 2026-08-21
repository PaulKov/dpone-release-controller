/** Exact direct capabilities of reviewed verifier/data transforms (B). */
export const REVIEWED_LOCAL_DATA_FLOW_CAPABILITIES_B = Object.freeze({
  "provider-quarantine-ast-simulations.mjs#assertAstProviderSimulations": Object.freeze([]),
  "provider-quarantine-ast-graph.mjs#reachable": caps(
    "injected-call:graph.get|injected-call:guarded.has|injected-call:pending.pop|injected-call:pending.push|injected-reference:caller.edges|injected-reference:edge|injected-reference:key|injected-reference:pending.length|injected-reference:start",
  ),
  "provider-quarantine-ast-graph.mjs#resolvesToFunction": caps(
    "injected-call:aliases.get|injected-call:aliases.has|injected-call:graph.has|injected-call:seen.add|injected-call:seen.has|injected-reference:alias|injected-reference:current|injected-reference:target",
  ),
  "provider-quarantine-ast-lexical.mjs#addBindingOrigin": caps(
    "injected-call:lexical.get|injected-reference:identifier|injected-reference:origin|injected-reference:originsByBinding",
  ),
  "provider-quarantine-ast-lexical.mjs#addOrigins": caps(
    "injected-call:current.add|injected-call:originsByBinding.get|injected-call:originsByBinding.set|injected-reference:before|injected-reference:binding|injected-reference:current|injected-reference:current.size|injected-reference:origin|injected-reference:origins",
  ),
  "provider-quarantine-ast-lexical.mjs#addPatternOrigins": caps(
    "injected-call:lexical.get|injected-call:pattern.reduce|injected-reference:changed|injected-reference:key|injected-reference:lexical|injected-reference:origins|injected-reference:originsByBinding|injected-reference:pattern|injected-reference:pattern.argument|injected-reference:pattern.left|injected-reference:pattern.properties|injected-reference:pattern.type|injected-reference:projected|injected-reference:property|injected-reference:property.argument|injected-reference:property.type|injected-reference:property.value|injected-reference:target",
  ),
  "provider-quarantine-ast-lexical.mjs#assignmentFlow": caps(
    "injected-reference:node.id|injected-reference:node.init|injected-reference:node.left|injected-reference:node.right|injected-reference:node.type|injected-reference:target",
  ),
  "provider-quarantine-ast-lexical.mjs#bindingIdentifier": caps(
    "injected-reference:name|injected-reference:node|injected-reference:node.name|injected-reference:node.type|injected-reference:pattern|injected-reference:pattern.name|injected-reference:pattern.type",
  ),
  "provider-quarantine-ast-lexical.mjs#buildLexicalReferenceIndex": caps(
    "injected-reference:identifier|injected-reference:manager.scopes|injected-reference:program|injected-reference:reference.identifier|injected-reference:reference.resolved|injected-reference:scope.references|injected-reference:scope.variables|injected-reference:variable|injected-reference:variable.identifiers",
  ),
  "provider-quarantine-ast-lexical.mjs#buildRegionValueFlow": caps(
    "injected-reference:changed|injected-reference:entries|injected-reference:flow|injected-reference:flow.source|injected-reference:flow.target|injected-reference:lexical|injected-reference:node|injected-reference:result|injected-reference:root|injected-reference:sourceOrigins|injected-reference:sourceOrigins.size",
  ),
  "provider-quarantine-ast-lexical.mjs#callResultOrigins": caps(
    "injected-call:caller.has|injected-call:caller.some|injected-call:origins.has|injected-call:originsForExpression|injected-reference:active|injected-reference:argument|injected-reference:argument.argument|injected-reference:argument.type|injected-reference:node.arguments|injected-reference:node.callee|injected-reference:origins|injected-reference:value",
  ),
  "provider-quarantine-ast-lexical.mjs#callerRoot": caps(
    "injected-call:caller.has|injected-call:originsForExpression|injected-reference:current|injected-reference:current.name|injected-reference:current.object|injected-reference:current.type|injected-reference:expression",
  ),
  "provider-quarantine-ast-lexical.mjs#childOrigins": caps(
    "injected-call:originsForExpression|injected-reference:active|injected-reference:child|injected-reference:child.type|injected-reference:children|injected-reference:key|injected-reference:node|injected-reference:origin|injected-reference:value",
  ),
  "provider-quarantine-ast-lexical.mjs#identifierOrigins": caps(
    "injected-call:lexical.get|injected-call:lexical.has|injected-call:originsByBinding.get|injected-reference:binding|injected-reference:identifier|injected-reference:identifier.name",
  ),
  "provider-quarantine-ast-lexical.mjs#isFunctionNode": caps("injected-reference:node"),
  "provider-quarantine-ast-lexical.mjs#projectOrigins": caps(
    "injected-call:origin.startsWith|injected-reference:computed|injected-reference:origin|injected-reference:origins|injected-reference:property",
  ),
  "provider-quarantine-ast-lexical.mjs#propertyName": caps(
    "injected-reference:property.computed|injected-reference:property.name|injected-reference:property.type|injected-reference:property.value",
  ),
  "provider-quarantine-ast-lexical.mjs#seedCallableBindings": caps(
    "injected-reference:entries|injected-reference:identifier|injected-reference:lexical|injected-reference:name|injected-reference:node|injected-reference:node.id|injected-reference:node.init|injected-reference:node.type|injected-reference:originsByBinding",
  ),
  "provider-quarantine-ast-lexical.mjs#seedCallableInputs": caps(
    "injected-reference:identifier|injected-reference:lexical|injected-reference:name|injected-reference:originsByBinding|injected-reference:parameter|injected-reference:root|injected-reference:root.params",
  ),
  "provider-quarantine-ast-ownership.mjs#assertCapabilityOwnership": caps(
    "injected-call:guarded.has|injected-call:modules.values|injected-reference:effectModules|injected-reference:exported|injected-reference:graph|injected-reference:guarded|injected-reference:localOwnerDigests|injected-reference:localOwners|injected-reference:module.exportedFunctionKeys|injected-reference:module.moduleKey|injected-reference:modules",
  ),
  "provider-quarantine-ast-ownership.mjs#assertEveryCapabilityHasOwner": caps(
    "injected-call:owned.add|injected-call:owned.has|injected-reference:graph|injected-reference:guarded|injected-reference:key|injected-reference:localOwners|injected-reference:node|injected-reference:node.size|injected-reference:owner",
  ),
  "provider-quarantine-ast-ownership.mjs#assertNoDangerousReachability": caps(
    "injected-call:caller.join|injected-call:graph.get|injected-call:guarded.has|injected-reference:caller.capabilities|injected-reference:capabilities|injected-reference:capabilities.size|injected-reference:effectModules|injected-reference:graph|injected-reference:guarded|injected-reference:key|injected-reference:localOwnerDigests|injected-reference:localOwners|injected-reference:localOwners.?|injected-reference:start",
  ),
  "provider-quarantine-ast-ownership.mjs#assertPinnedLocalCapabilityCalls": caps(
    "injected-call:caller.get|injected-call:caller.sort|injected-call:key.split|injected-call:modules.get|injected-reference:expected|injected-reference:filename|injected-reference:key|injected-reference:localOwners|injected-reference:node|injected-reference:node.capabilities",
  ),
  "provider-quarantine-ast-ownership.mjs#assertRestrictedOwnerReachability": caps(
    "injected-call:capabilities.some|injected-call:effectModules.has|injected-call:start.split|injected-reference:localOwnerDigests|injected-reference:owner|injected-reference:restricted|injected-reference:start|injected-reference:startModule",
  ),
  "provider-quarantine-ast-ownership.mjs#normalizedAstDigest": caps(
    "injected-call:caller.digest|injected-call:caller.update|injected-call:createHash|injected-reference:canonical|injected-reference:node",
  ),
  "provider-quarantine-ast-simulations.mjs#assertCentralSimulationBoundaries": caps(
    "injected-reference:declaration.?|injected-reference:declaration.name|injected-reference:exports|injected-reference:first|injected-reference:parameter|injected-reference:program|injected-reference:symbol",
  ),
  "provider-quarantine-ast-simulations.mjs#assertSameInventory": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:actualIterable|injected-reference:expected|injected-reference:expectedIterable",
  ),
  "provider-quarantine-ast-simulations.mjs#assertUnshadowedLocalFunction": caps(
    "injected-call:node.some|injected-reference:name|injected-reference:node.argument|injected-reference:node.id|injected-reference:node.left|injected-reference:node.name|injected-reference:node.type|injected-reference:program|injected-reference:target",
  ),
  "provider-quarantine-ast-simulations.mjs#assertWrapperBoundary": caps(
    "injected-reference:call.length|injected-reference:call.name|injected-reference:call.optional|injected-reference:call.type|injected-reference:declaration.body|injected-reference:declaration.name|injected-reference:descriptor|injected-reference:filename|injected-reference:imported|injected-reference:parameter|injected-reference:program|injected-reference:source|injected-reference:statements.argument|injected-reference:statements.length|injected-reference:statements.type|injected-reference:symbol",
  ),
  "provider-quarantine-ast-simulations.mjs#bindingIncludes": caps(
    "injected-call:caller.some|injected-reference:name|injected-reference:pattern",
  ),
  "provider-quarantine-ast-simulations.mjs#isPrimitiveStringGuard": caps(
    "injected-reference:consequent.type|injected-reference:parameter|injected-reference:statement.?|injected-reference:statement.alternate|injected-reference:statement.consequent|injected-reference:statement.length|injected-reference:statement.test|injected-reference:statement.type|injected-reference:test.name|injected-reference:test.operator|injected-reference:test.type|injected-reference:test.value",
  ),
  "provider-quarantine-ast-simulations.mjs#isSealedParserAssignment": caps(
    "injected-reference:call.length|injected-reference:call.name|injected-reference:call.optional|injected-reference:call.type|injected-reference:declaration.init|injected-reference:declaration.type|injected-reference:parameter|injected-reference:statement.?|injected-reference:statement.kind|injected-reference:statement.length|injected-reference:statement.type",
  ),
  "provider-quarantine-ast-simulations.mjs#requirePrimitiveFunction": caps(
    "injected-reference:declaration|injected-reference:declaration.async|injected-reference:declaration.generator|injected-reference:declaration.length|injected-reference:declaration.type|injected-reference:filename|injected-reference:program|injected-reference:symbol",
  ),
  "provider-quarantine-ast-utils.mjs#bindingNames": caps(
    "injected-call:pattern.flatMap|injected-reference:pattern.argument|injected-reference:pattern.left|injected-reference:pattern.name|injected-reference:pattern.type",
  ),
  "provider-quarantine-ast-utils.mjs#expressionUsesTaint": caps(
    "injected-call:caller.some|injected-call:tainted.has|injected-reference:node",
  ),
  "provider-quarantine-ast-utils.mjs#isEscapeParent": caps(
    "injected-reference:node|injected-reference:parent.callee|injected-reference:parent.type|injected-reference:parent.value",
  ),
  "provider-quarantine-ast-utils.mjs#isFunction": caps("injected-reference:node.type"),
  "provider-quarantine-ast-utils.mjs#isNonReferenceIdentifier": caps(
    "injected-call:parent.includes|injected-reference:node|injected-reference:parent|injected-reference:parent.computed|injected-reference:parent.id|injected-reference:parent.key|injected-reference:parent.property|injected-reference:parent.type|injected-reference:parent.value",
  ),
  "provider-quarantine-ast-utils.mjs#memberProperty": caps(
    "injected-reference:member.computed|injected-reference:member.name|injected-reference:member.type|injected-reference:member.value",
  ),
  "provider-quarantine-ast-utils.mjs#memberRoot": caps(
    "injected-reference:current|injected-reference:current.name|injected-reference:current.object|injected-reference:current.type|injected-reference:member",
  ),
  "provider-quarantine-ast-utils.mjs#regionEntries": caps(
    "injected-call:skipped.has|injected-reference:root|injected-reference:skipped",
  ),
  "provider-quarantine-ast-utils.mjs#unwrapChain": caps(
    "injected-reference:node|injected-reference:node.expression|injected-reference:node.type",
  ),
  "provider-quarantine-effect-data.mjs#assertExactDescriptors": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:actual.?|injected-reference:actualKeys",
  ),
  "provider-quarantine-effect-data.mjs#assertExactEffectDataExports": caps(
    "injected-reference:declaration.declarations|injected-reference:declaration.kind|injected-reference:declaration.type|injected-reference:filename|injected-reference:item.init|injected-reference:item.name|injected-reference:item.type|injected-reference:program|injected-reference:program.body|injected-reference:programs|injected-reference:statement.declaration|injected-reference:statement.type",
  ),
  "provider-quarantine-effect-data.mjs#descriptor": caps(
    "injected-reference:origin|injected-reference:sha256|injected-reference:type",
  ),
  "provider-quarantine-effect-data.mjs#initializerOrigin": caps(
    "injected-reference:imported|injected-reference:initializer.name|injected-reference:initializer.type|injected-reference:program.body|injected-reference:specifier.name|injected-reference:specifier.type|injected-reference:statement.specifiers|injected-reference:statement.type|injected-reference:statement.value",
  ),
  "provider-quarantine-filesystem.mjs#readRegularContainedScripts": caps(
    "filesystem-read:lstatSync|filesystem-read:readFileSync|filesystem-read:realpathSync|injected-call:metadata.isFile|injected-call:metadata.isSymbolicLink|injected-call:rootMetadata.isDirectory|injected-call:source.startsWith|injected-reference:bytes|injected-reference:filename|injected-reference:filename.length|injected-reference:filenames|injected-reference:path|injected-reference:resolved|injected-reference:root|injected-reference:rootInput|injected-reference:rootUrl|injected-reference:source|intrinsic-reference:intrinsic:URL",
  ),
  "provider-quarantine-inventory.mjs#item": caps(
    "injected-reference:entrypoint|injected-reference:module|injected-reference:symbol",
  ),
  "provider-quarantine-policy.mjs#assertPinnedProviderBoundarySources": caps(
    "injected-reference:sources",
  ),
  "provider-quarantine-policy.mjs#assertProductionGraphExcludesTests": caps(
    "injected-call:node.startsWith|injected-call:nodes.filter|injected-reference:dynamicImports.length|injected-reference:dynamicImports.type|injected-reference:dynamicImports.value|injected-reference:filename|injected-reference:node.source|injected-reference:node.type|injected-reference:nodes|injected-reference:program|injected-reference:source|injected-reference:sources|injected-reference:trustedBootstrapImport",
  ),
  "provider-quarantine-policy.mjs#assertProductionScriptInventory": caps(
    "injected-call:actualScripts.some|injected-call:sources.get|injected-reference:sources",
  ),
  "provider-quarantine-policy.mjs#assertProviderBoundarySources": caps(
    "injected-reference:boundaries|injected-reference:entrypoints|injected-reference:sources",
  ),
  "provider-quarantine-policy.mjs#assertProviderPackageScripts": caps(
    "injected-call:caller.sort|injected-reference:packageJson.?|injected-reference:packageJson.espree|injected-reference:packageJson.node|injected-reference:packageJson.packageManager|injected-reference:packageJson.scripts",
  ),
  "provider-quarantine-policy.mjs#assertProviderSimulationsAreDataOnly": caps(
    "injected-reference:actual|injected-reference:sources",
  ),
  "provider-quarantine-policy.mjs#assertSupportedExportSyntax": caps(
    "injected-reference:filename|injected-reference:source",
  ),
  "provider-quarantine-reviewed-data-flows-a.mjs#caps": caps("injected-call:value.split"),
  "provider-quarantine-reviewed-data-flows-b.mjs#caps": caps("injected-call:value.split"),
  "provider-quarantine-simulation-program.mjs#assertSimulationProgramShell": caps(
    "injected-reference:declaration.declarations|injected-reference:declaration.kind|injected-reference:declaration.type|injected-reference:filename|injected-reference:item.init|injected-reference:item.type|injected-reference:program|injected-reference:program.body|injected-reference:statement|injected-reference:statement.declaration|injected-reference:statement.type",
  ),
  "provider-quarantine-simulation-program.mjs#isFunctionDeclaration": caps(
    "injected-reference:statement.type",
  ),
  "provider-quarantine-simulation-program.mjs#isPrimitiveArray": caps(
    "injected-call:value.every|injected-reference:value.type",
  ),
  "provider-quarantine-simulation-program.mjs#isSealedDataInitializer": caps(
    "injected-reference:initializer.?|injected-reference:initializer.computed|injected-reference:initializer.length|injected-reference:initializer.name|injected-reference:initializer.regex|injected-reference:initializer.type",
  ),
  "provider-quarantine-simulation-purity.mjs#assertExactDigestMap": caps(
    "injected-call:caller.sort|injected-reference:actual|injected-reference:actual.?|injected-reference:actualKeys|injected-reference:expected|injected-reference:expected.?|injected-reference:expectedKeys|injected-reference:key",
  ),
  "provider-quarantine-simulation-purity.mjs#assertNoIntrinsicShadowing": caps(
    "injected-call:bindings.some|injected-call:caller.some|injected-call:node.flatMap|injected-call:node.map|injected-reference:filename|injected-reference:node.argument|injected-reference:node.id|injected-reference:node.left|injected-reference:node.name|injected-reference:node.param|injected-reference:node.type|injected-reference:program",
  ),
  "provider-quarantine-simulation-purity.mjs#assertNoMemberAlias": caps(
    "injected-reference:filename|injected-reference:member|injected-reference:method|injected-reference:parent.callee|injected-reference:parent.type",
  ),
  "provider-quarantine-simulation-purity.mjs#assertPureCall": caps(
    "injected-call:lexical.get|injected-call:reviewedCallBindings.has|injected-reference:call.arguments|injected-reference:call.callee|injected-reference:call.computed|injected-reference:call.name|injected-reference:call.object|injected-reference:call.optional|injected-reference:call.type|injected-reference:filename|injected-reference:lexical|injected-reference:localFunctions|injected-reference:method|injected-reference:owner|injected-reference:pair|injected-reference:receiver|injected-reference:reviewedCallBindings",
  ),
  "provider-quarantine-simulation-purity.mjs#assertPureCallbackArguments": caps(
    "injected-call:lexical.get|injected-call:localFunctions.has|injected-call:reviewedCallBindings.has|injected-reference:arguments_.?|injected-reference:callback|injected-reference:callback.name|injected-reference:callback.type|injected-reference:filename",
  ),
  "provider-quarantine-simulation-purity.mjs#assertPureConstructor": caps(
    "injected-reference:expression.callee|injected-reference:expression.name|injected-reference:expression.type|injected-reference:filename|injected-reference:lexical",
  ),
  "provider-quarantine-simulation-purity.mjs#assertPureProgram": caps(
    "injected-call:functions.keys|injected-call:functions.values|injected-call:lexical.get|injected-call:ownerByNode.get|injected-call:topLevelFunctions.has|injected-reference:binding|injected-reference:declaration.id|injected-reference:filename|injected-reference:lexical|injected-reference:localFunctions|injected-reference:node|injected-reference:node.name|injected-reference:node.type|injected-reference:parent|injected-reference:program|injected-reference:program.body|injected-reference:specifier.local|injected-reference:statement.specifiers|injected-reference:statement.type",
  ),
  "provider-quarantine-simulation-purity.mjs#assertPureSimulationPrograms": caps(
    "injected-reference:declaration|injected-reference:expectedDigests|injected-reference:filename|injected-reference:functions|injected-reference:lexical|injected-reference:name|injected-reference:ownerByNode|injected-reference:program|injected-reference:programs",
  ),
  "provider-quarantine-simulation-purity.mjs#collectTopLevelFunctions": caps(
    "injected-call:declaration.some|injected-reference:declaration|injected-reference:declaration.id|injected-reference:declaration.name|injected-reference:declaration.type|injected-reference:filename|injected-reference:program.body|injected-reference:statement|injected-reference:statement.declaration|injected-reference:statement.type",
  ),
  "provider-quarantine-simulation-purity.mjs#indexFunctionOwners": caps(
    "injected-call:caller.map|injected-call:names.get|injected-reference:current|injected-reference:functions|injected-reference:program",
  ),
  "provider-quarantine-simulation-purity.mjs#isDirectMapCallback": caps(
    "injected-call:parent.includes|injected-reference:node|injected-reference:parent.computed|injected-reference:parent.name|injected-reference:parent.type",
  ),
  "provider-quarantine-simulation-purity.mjs#isFrozenArray": caps(
    "injected-reference:expression.callee|injected-reference:expression.length|injected-reference:expression.object|injected-reference:expression.type|injected-reference:lexical",
  ),
  "provider-quarantine-simulation-purity.mjs#isUnshadowedGlobal": caps(
    "injected-call:lexical.has|injected-reference:identifier|injected-reference:identifier.type",
  ),
  "provider-quarantine-simulation-purity.mjs#isUnshadowedSetConstruction": caps(
    "injected-reference:expression.callee|injected-reference:expression.name|injected-reference:expression.type|injected-reference:lexical",
  ),
  "provider-quarantine-simulation-purity.mjs#memberName": caps(
    "injected-reference:member.computed|injected-reference:member.name|injected-reference:member.type|injected-reference:member.value",
  ),
  "provider-quarantine-simulation-purity.mjs#normalizedAstDigest": caps(
    "injected-call:caller.digest|injected-reference:canonical|injected-reference:node",
  ),
  "provider-quarantine-simulation-purity.mjs#receiverKind": caps(
    "injected-call:lexical.get|injected-reference:definition.init|injected-reference:definition.type|injected-reference:expression|injected-reference:expression.name|injected-reference:expression.regex|injected-reference:expression.type|injected-reference:initializer|injected-reference:initializer.name|injected-reference:initializer.regex|injected-reference:initializer.type|injected-reference:lexical|injected-reference:owner|injected-reference:variable.?|injected-reference:variable.length",
  ),
  "provider-quarantine-simulation-purity.mjs#staticMemberPair": caps(
    "injected-reference:member.name|injected-reference:member.type",
  ),
  "provision-cloudflare-deployment-observer-token.mjs#<module>": caps(
    "native-entry-dispatch:process.argv[1]",
  ),
  "provision-github-app-key.mjs#<module>": caps("native-entry-dispatch:process.argv[1]"),
  "provision-worm-rpc-key.mjs#<module>": caps("native-entry-dispatch:process.argv[1]"),
  "publication-privacy-policy.mjs#asciiCompare": caps(
    "injected-reference:left|injected-reference:right",
  ),
  "publication-privacy-policy.mjs#assertNoCredentialMaterial": caps(
    "injected-reference:path|injected-reference:source",
  ),
  "publication-privacy-policy.mjs#assertNoForbiddenPublicationValue": caps(
    "injected-reference:path|injected-reference:source",
  ),
  "publication-privacy-policy.mjs#assertPublicationTextPath": caps(
    "injected-reference:extension|injected-reference:path",
  ),
  "publication-privacy-policy.mjs#assertPublishableDocument": caps(
    "injected-call:source.includes|injected-reference:path|injected-reference:source",
  ),
  "publication-privacy-policy.mjs#assertPublishableLiveConfig": caps(
    "injected-call:accountIds.some|injected-call:caller.filter|injected-call:caller.sort|injected-call:source.match|injected-call:source.startsWith|injected-reference:actualKeys|injected-reference:config.account_id|injected-reference:config.vars|injected-reference:filename|injected-reference:vars|injected-reference:vars.?",
  ),
  "publication-privacy-policy.mjs#decodePublicationText": caps(
    "injected-reference:bytes|injected-reference:path",
  ),
  "publication-privacy-policy.mjs#isForbiddenSecretArtifact": caps("injected-reference:path"),
  "publication-privacy-policy.mjs#requireRecord": caps(
    "injected-reference:name|injected-reference:value",
  ),
  "reviewed-jsonc.mjs#parseReviewedJsonc": caps(
    "injected-call:source.slice|injected-call:source.startsWith|injected-reference:body.?|injected-reference:body.length|injected-reference:character|injected-reference:path|injected-reference:result|injected-reference:source",
  ),
  "upload-version.mjs#<module>": caps("native-entry-dispatch:process.argv[1]"),
  "verify-project-config.mjs#<module>": caps(
    "filesystem-read:existsSync|filesystem-read:readFileSync|filesystem-read:readdirSync",
  ),
});

function caps(value) {
  return Object.freeze(value.split("|"));
}
