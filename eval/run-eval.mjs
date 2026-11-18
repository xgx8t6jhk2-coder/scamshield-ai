import { readFile, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { analyzeMessage, analyzeUrl, ENGINE_VERSION } from '../public/engine/scamshield.js';

const [corpusPath = new URL('corpus.json', import.meta.url),
  outputPath = new URL('RESULTS.md', import.meta.url)] = process.argv.slice(2);
const corpus = JSON.parse(await readFile(corpusPath, 'utf8'));
const rows = corpus.map((item) => {
  const started = performance.now();
  let result;
  try {
    result = item.type === 'url' ? analyzeUrl(item.text) : analyzeMessage(item.text, { sender: item.sender });
  } catch (error) {
    throw new Error(`Engine failed on ${item.id}`, { cause: error });
  }
  return { item, result, ms: performance.now() - started, predicted: result.verdict !== 'safe' };
});

function divide(numerator, denominator) {
  return denominator ? numerator / denominator : null;
}

function metrics(group) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (const { item, predicted } of group) {
    if (item.label === 'scam') predicted ? tp++ : fn++;
    else predicted ? fp++ : tn++;
  }
  return {
    tp, tn, fp, fn,
    accuracy: divide(tp + tn, group.length),
    precision: divide(tp, tp + fp),
    recall: divide(tp, tp + fn),
    f1: divide(2 * tp, 2 * tp + fp + fn),
    specificity: divide(tn, tn + fp),
  };
}

function groupBy(key) {
  const groups = new Map();
  for (const row of rows) {
    const value = row.item[key];
    if (!groups.has(value)) groups.set(value, []);
    groups.get(value).push(row);
  }
  return [...groups].sort(([left], [right]) => left.localeCompare(right));
}

function percent(value) {
  return value === null ? '—' : (value * 100).toFixed(2) + '%';
}

const total = metrics(rows);
const times = rows.map(({ ms }) => ms).sort((left, right) => left - right);
const mean = times.reduce((sum, time) => sum + time, 0) / times.length;
const p95 = times[Math.ceil(times.length * 0.95) - 1];
const scamMessages = rows.filter(({ item }) => item.type === 'message' && item.label === 'scam').length;
const benignMessages = rows.filter(({ item }) => item.type === 'message' && item.label === 'benign').length;

const report = [
  '# ScamShield evaluation',
  '',
  `Engine ${ENGINE_VERSION} · ${rows.length} samples · Node ${process.version}`,
  '',
  `Corpus mix includes ${scamMessages} scam messages, ${benignMessages} benign messages, and ${rows.length - scamMessages - benignMessages} URLs.`,
  'The positive class is scam. Both suspicious and dangerous verdicts count as positive.',
  '',
  '| Accuracy | Precision | Recall | F1 |',
  '| ---: | ---: | ---: | ---: |',
  `| ${[total.accuracy, total.precision, total.recall, total.f1].map(percent).join(' | ')} |`,
  '',
  '## Confusion matrix',
  '',
  '| Actual | Predicted scam | Predicted benign |',
  '| --- | ---: | ---: |',
  `| Scam | ${total.tp} | ${total.fn} |`,
  `| Benign | ${total.fp} | ${total.tn} |`,
  '',
  '## Per-category recall',
  '',
  'A dash indicates a zero denominator. Specificity measures the share of benign samples classified as benign.',
  '',
  '| Category | Scam | Benign | Recall | Specificity |',
  '| --- | ---: | ---: | ---: | ---: |',
  ...groupBy('category').map(([key, group]) => {
    const m = metrics(group);
    return `| ${key} | ${m.tp + m.fn} | ${m.tn + m.fp} | ${percent(m.recall)} | ${percent(m.specificity)} |`;
  }),
  '',
  '## Per-language metrics',
  '',
  '| Language | Samples | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |',
  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ...groupBy('lang').map(([key, group]) => {
    const m = metrics(group);
    const rates = [m.accuracy, m.precision, m.recall, m.f1].map(percent).join(' | ');
    return `| ${key} | ${group.length} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${rates} |`;
  }),
  '',
  '## Latency',
  '',
  `Mean **${mean.toFixed(3)} ms** per item. Nearest-rank p95 **${p95.toFixed(3)} ms** per item.`,
  'Timing covers a single pass of individual engine calls and includes cold calls.',
];

function addErrors(heading, label, predicted) {
  const errors = rows.filter((row) => row.item.label === label && row.predicted === predicted);
  report.push('', `## ${heading} (${errors.length})`, '');
  if (!errors.length) {
    report.push('None.');
    return;
  }
  report.push('| Corpus ID | Type | Language | Category | Verdict | Score | Signals (weight) |',
    '| --- | --- | --- | --- | --- | ---: | --- |');
  for (const { item, result } of errors) {
    const signals = [...result.signals.map((signal) => `${signal.id} (${signal.weight})`)];
    for (const link of result.links ?? []) {
      for (const signal of link.signals) signals.push(`link: ${signal.id} (${signal.weight})`);
    }
    report.push(`| ${item.id} | ${item.type} | ${item.lang} | ${item.category} | ${result.verdict} | ${result.score} | ${signals.join(', ') || '—'} |`);
  }
}

addErrors('False positives', 'benign', true);
addErrors('False negatives', 'scam', false);
const markdown = report.join('\n') + '\n';
await writeFile(outputPath, markdown);
process.stdout.write(markdown);
