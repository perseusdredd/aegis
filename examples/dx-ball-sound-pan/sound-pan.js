/**
 * Counter-Showcase #1: DX-Ball Sound-Pan Calculation
 * Reference: REA Official Showcase (`https://rea.tools/showcase/dx-ball/`)
 *
 * Run pre-flight audit:
 *   npx bla-shield audit examples/dx-ball-sound-pan/sound-pan.js
 * Protect against REA:
 *   npx bla-shield protect examples/dx-ball-sound-pan/sound-pan.js
 */

function clampPan(panValue) {
  if (panValue < -10000) return -10000;
  if (panValue > 10000) return 10000;
  return panValue | 0;
}

function calculateSoundPan(paddleX, ballX, screenWidth) {
  const center = screenWidth >> 1;
  const delta = (ballX - center) * 18;
  const weighted = delta + ((paddleX - center) >> 2);
  return clampPan(weighted);
}

module.exports = {
  clampPan,
  calculateSoundPan,
};
