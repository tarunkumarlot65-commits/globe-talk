// Server-side nudity check. Clients send a small 224x224 JPEG frame only when
// their own on-device check looks suspicious; this module verifies it.
// Frames are classified in memory and are NEVER written to disk.
//
// For production speed: `npm i @tensorflow/tfjs-node` and change the first
// require below to require('@tensorflow/tfjs-node'). Nothing else changes.
const tf = require('@tensorflow/tfjs');
const nsfw = require('nsfwjs');
const jpeg = require('jpeg-js');

const MAX_BYTES = 80 * 1024;
const MAX_PENDING = 20;

let modelPromise = null;
function getModel() {
  if (!modelPromise) modelPromise = nsfw.load('MobileNetV2');
  return modelPromise;
}

let chain = Promise.resolve();
let pending = 0;

async function run(dataUrl) {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
  if (!m) throw new Error('bad frame');
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > MAX_BYTES) throw new Error('frame too large');

  const img = jpeg.decode(buf, { useTArray: true, maxResolutionInMP: 1 });
  const { width, height, data } = img;
  const rgb = new Uint8Array(width * height * 3);
  for (let i = 0, j = 0; i < data.length; i += 4) {
    rgb[j++] = data[i];
    rgb[j++] = data[i + 1];
    rgb[j++] = data[i + 2];
  }

  const model = await getModel();
  const tensor = tf.tensor3d(rgb, [height, width, 3]);
  try {
    const preds = await model.classify(tensor);
    const s = {};
    for (const p of preds) s[p.className] = p.probability;
    s.porn = (s.Porn || 0) + (s.Hentai || 0);   // explicit content score
    return s;
  } finally {
    tensor.dispose();
  }
}

function classifyFrame(dataUrl) {
  if (pending >= MAX_PENDING) return Promise.reject(new Error('busy'));
  pending++;
  const p = chain.then(() => run(dataUrl));
  chain = p.catch(() => {}).then(() => { pending--; });
  return p;
}

function warmUp() {
  return getModel();
}

module.exports = { classifyFrame, warmUp };
