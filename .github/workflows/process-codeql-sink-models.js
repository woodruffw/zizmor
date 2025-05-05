/*
 * Processes the CodeQL models from https://github.com/github/codeql/tree/main/actions/ql/lib/ext
 * and extracts the information needed by zizmor
 */

// @ts-check

const path = require('node:path')
const fs = require('node:fs')
// yaml library is installed by GitHub workflow
const yaml = require('../../codeql-models-working-dir/node_modules/yaml')

/** @type Map<string, string[]> */
const codeInjectionSinks = new Map()

/**
 * @param {fs.PathLike} filePath
 * @param {Set<string>} relevantKinds which sink kinds are relevant
 * @param {boolean} onlyManualModels whether to include only models with 'provenance == manual'
 */
function processYamlFile(filePath, relevantKinds, onlyManualModels) {
    const content = yaml.parse(fs.readFileSync(filePath, { encoding: 'utf8' }))
    const extensions = content['extensions']

    if (extensions === undefined) {
        throw new Error('Missing extensions: ' + content)
    }

    for (const extension of extensions) {
        const addsTo = extension['addsTo']
        if (addsTo === undefined) {
            throw new Error('Missing addsTo: ' + content)
        }

        const extensible = addsTo['extensible']
        if (extensible !== 'actionsSinkModel') {
            continue
        }

        const pack = addsTo['pack']
        // Fail if CodeQL starts using other packs, have to examine then what this means,
        // e.g. whether it has lower accuracy or severity
        if (pack !== 'codeql/actions-all') {
            throw new Error('Unexpected pack: ' + pack)
        }

        const data = extension['data']
        if (data === undefined) {
            throw new Error('Missing data: ' + content)
        }

        for (const dataEntry of data) {
            if (dataEntry.length !== 5) {
                throw new Error('Contains malformed data entry: ' + dataEntry)
            }

            // See https://github.com/github/codeql/blob/codeql-cli/v2.21.2/actions/ql/lib/codeql/actions/dataflow/internal/ExternalFlowExtensions.qll#L22-L24
            /** @type string[] */
            const [action, version, input, kind, provenance] = dataEntry
            if (!relevantKinds.has(kind)) {
                continue
            }
            if (onlyManualModels && provenance !== 'manual') {
                continue
            }

            // Ignore 'on: workflow_call' inputs; seems to be mostly for 'generated' models
            if (action.includes('/.github/workflows/')) {
                continue
            }

            // Currently all models use only '*' as affected version, so for simplicity only
            // support that for now
            if (version !== '*') {
                throw new Error(
                    'Non-wildcard versions are not supported yet: ' + version
                )
            }

            const inputPrefix = 'input.'
            if (!input.startsWith(inputPrefix)) {
                throw new Error('Contains input with unexpected format: ' + input)
            }
            const inputName = input.substring(inputPrefix.length)

            let inputs = codeInjectionSinks.get(action)
            if (inputs === undefined) {
                inputs = []
                codeInjectionSinks.set(action, inputs)
            }
            inputs.push(inputName)
        }
    }
}

/**
 * @param {string} codeQlDir
 * @param {fs.PathLike} outputFile
 */
function processModels(codeQlDir, outputFile) {
    const modelsDir = path.join(codeQlDir, 'actions/ql/lib/ext')
    const files = fs.readdirSync(modelsDir, {
        recursive: true,
        withFileTypes: true,
    })

    const relevantKinds = new Set(['code-injection'])
    // For now only include models manually curated by the CodeQL developers
    const onlyManualModels = true

    let processedCount = 0
    for (const file of files) {
        if (file.isFile()) {
            const name = file.name
            if (name.endsWith('.yml') || name.endsWith('.yaml')) {
                processedCount++
                const filePath = path.join(file.parentPath, name)
                try {
                    processYamlFile(filePath, relevantKinds, onlyManualModels)
                } catch (e) {
                    throw new Error('Failed processing file: ' + filePath, { cause: e })
                }
            }
        }
    }

    console.info(`Processed ${processedCount} files`)

    // Important: Data format must match the parsing logic in the Rust code
    const zizmorModelData = [...codeInjectionSinks].sort().map(entry => `${entry[0]}|${entry[1].join(',')}\n`).join('')
    fs.writeFileSync(outputFile, zizmorModelData)
    console.info(`Wrote model data to file: ${outputFile}`)
}

processModels('codeql', '../code-injection-models.txt')
