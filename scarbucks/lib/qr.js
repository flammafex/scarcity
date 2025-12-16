/**
 * Scarbucks QR Code Generator
 * Generates red-on-black QR codes for the VirtualBoy aesthetic
 * Minimal implementation optimized for URLs
 */

const ScarbucksQR = (() => {
  // QR Code constants
  const EC_LEVEL = 1; // L = 0, M = 1, Q = 2, H = 3

  // Alphanumeric character set
  const ALPHANUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

  // Error correction codewords and blocks per version (M level)
  const EC_TABLE = [
    null, // version 0 doesn't exist
    [10, 1], // v1: 10 EC codewords, 1 block
    [16, 1], // v2
    [26, 1], // v3
    [18, 2], // v4
    [24, 2], // v5
    [16, 4], // v6
    [18, 4], // v7
    [22, 4], // v8
    [22, 5], // v9
    [26, 5], // v10
  ];

  // Data capacity per version (M level, byte mode)
  const CAPACITY = [0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213];

  // Generator polynomials for Reed-Solomon
  const GEN_POLY = {
    10: [0, 251, 67, 46, 61, 118, 70, 64, 94, 32, 45],
    16: [0, 120, 104, 107, 109, 102, 161, 76, 3, 91, 191, 147, 169, 182, 194, 225, 120],
    18: [0, 215, 234, 158, 94, 184, 97, 118, 170, 79, 187, 152, 148, 252, 179, 5, 98, 96, 153],
    22: [0, 210, 171, 247, 242, 93, 230, 14, 109, 221, 53, 200, 74, 8, 172, 98, 80, 219, 134, 160, 105, 165, 231],
    24: [0, 229, 121, 135, 48, 211, 117, 251, 126, 159, 180, 169, 152, 192, 226, 228, 218, 111, 0, 117, 232, 87, 96, 227, 21],
    26: [0, 173, 125, 158, 2, 103, 182, 118, 17, 145, 201, 111, 28, 165, 53, 161, 21, 245, 142, 13, 102, 48, 227, 153, 145, 218, 70],
  };

  // Galois field arithmetic
  const GF = {
    exp: new Uint8Array(512),
    log: new Uint8Array(256),

    init() {
      let x = 1;
      for (let i = 0; i < 255; i++) {
        this.exp[i] = x;
        this.log[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;
      }
      for (let i = 255; i < 512; i++) {
        this.exp[i] = this.exp[i - 255];
      }
    },

    mul(a, b) {
      if (a === 0 || b === 0) return 0;
      return this.exp[this.log[a] + this.log[b]];
    }
  };

  GF.init();

  /**
   * Determine minimum QR version for data
   * @param {string} data
   * @returns {number}
   */
  function getVersion(data) {
    const len = new TextEncoder().encode(data).length;
    for (let v = 1; v <= 10; v++) {
      if (len <= CAPACITY[v]) return v;
    }
    throw new Error('Data too long for QR code');
  }

  /**
   * Get module size for version
   * @param {number} version
   * @returns {number}
   */
  function getSize(version) {
    return 17 + version * 4;
  }

  /**
   * Create empty matrix
   * @param {number} size
   * @returns {Array<Array<number>>}
   */
  function createMatrix(size) {
    return Array.from({ length: size }, () => Array(size).fill(0));
  }

  /**
   * Add finder patterns
   * @param {Array} matrix
   */
  function addFinderPatterns(matrix) {
    const size = matrix.length;

    const drawFinder = (r, c) => {
      for (let dr = -1; dr <= 7; dr++) {
        for (let dc = -1; dc <= 7; dc++) {
          const row = r + dr;
          const col = c + dc;
          if (row < 0 || row >= size || col < 0 || col >= size) continue;

          if (dr === -1 || dr === 7 || dc === -1 || dc === 7) {
            matrix[row][col] = 0; // Separator
          } else if (dr === 0 || dr === 6 || dc === 0 || dc === 6) {
            matrix[row][col] = 1;
          } else if (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4) {
            matrix[row][col] = 1;
          } else {
            matrix[row][col] = 0;
          }
        }
      }
    };

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);
  }

  /**
   * Add timing patterns
   * @param {Array} matrix
   */
  function addTimingPatterns(matrix) {
    const size = matrix.length;
    for (let i = 8; i < size - 8; i++) {
      const val = (i + 1) % 2;
      matrix[6][i] = val;
      matrix[i][6] = val;
    }
  }

  /**
   * Add alignment pattern (for version >= 2)
   * @param {Array} matrix
   * @param {number} version
   */
  function addAlignmentPattern(matrix, version) {
    if (version < 2) return;

    const size = matrix.length;
    const pos = size - 7;

    for (let dr = -2; dr <= 2; dr++) {
      for (let dc = -2; dc <= 2; dc++) {
        const row = pos + dr;
        const col = pos + dc;
        if (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) {
          matrix[row][col] = 1;
        } else {
          matrix[row][col] = 0;
        }
      }
    }
  }

  /**
   * Encode data to bytes (byte mode)
   * @param {string} data
   * @returns {Uint8Array}
   */
  function encodeData(data) {
    return new TextEncoder().encode(data);
  }

  /**
   * Create data codewords
   * @param {string} data
   * @param {number} version
   * @returns {Uint8Array}
   */
  function createDataCodewords(data, version) {
    const bytes = encodeData(data);
    const [ecCount] = EC_TABLE[version];
    const totalCodewords = Math.floor((getSize(version) ** 2 - 225 - (version > 1 ? 25 : 0)) / 8);
    const dataCodewords = totalCodewords - ecCount;

    const result = new Uint8Array(dataCodewords);
    let bitPos = 0;

    // Mode indicator: 0100 (byte mode)
    result[0] = 0x40;
    bitPos = 4;

    // Character count
    const countBits = version <= 9 ? 8 : 16;
    let count = bytes.length;

    if (countBits === 8) {
      result[0] |= (count >> 4) & 0x0f;
      result[1] = (count << 4) & 0xf0;
      bitPos = 12;
    }

    // Data
    let byteIndex = 1;
    let bitOffset = 4;

    for (const byte of bytes) {
      if (bitOffset === 0) {
        result[byteIndex++] = byte;
      } else {
        result[byteIndex] |= (byte >> bitOffset) & (0xff >> bitOffset);
        byteIndex++;
        if (byteIndex < dataCodewords) {
          result[byteIndex] = (byte << (8 - bitOffset)) & 0xff;
        }
      }
    }

    // Terminator
    byteIndex++;

    // Padding
    let pad = 0xec;
    while (byteIndex < dataCodewords) {
      result[byteIndex++] = pad;
      pad = pad === 0xec ? 0x11 : 0xec;
    }

    return result;
  }

  /**
   * Calculate error correction codewords
   * @param {Uint8Array} data
   * @param {number} ecCount
   * @returns {Uint8Array}
   */
  function calculateEC(data, ecCount) {
    const gen = GEN_POLY[ecCount];
    const result = new Uint8Array(ecCount);

    for (const byte of data) {
      const coef = byte ^ result[0];
      for (let i = 0; i < ecCount - 1; i++) {
        result[i] = result[i + 1] ^ GF.mul(gen[i + 1], coef);
      }
      result[ecCount - 1] = GF.mul(gen[ecCount], coef);
    }

    return result;
  }

  /**
   * Place data modules in matrix
   * @param {Array} matrix
   * @param {Uint8Array} data
   * @param {Uint8Array} ec
   */
  function placeData(matrix, data, ec) {
    const size = matrix.length;
    const allData = new Uint8Array(data.length + ec.length);
    allData.set(data);
    allData.set(ec, data.length);

    let bitIndex = 0;
    let up = true;

    for (let col = size - 1; col >= 0; col -= 2) {
      if (col === 6) col = 5; // Skip timing column

      for (let i = 0; i < size; i++) {
        const row = up ? size - 1 - i : i;

        for (let c = 0; c < 2; c++) {
          const curCol = col - c;
          if (matrix[row][curCol] !== 0 && matrix[row][curCol] !== 1) {
            continue; // Already set (finder, timing, etc.)
          }

          // Check if this is a reserved area
          if (isReserved(row, curCol, size)) continue;

          const bytePos = Math.floor(bitIndex / 8);
          const bitPos = 7 - (bitIndex % 8);

          if (bytePos < allData.length) {
            matrix[row][curCol] = (allData[bytePos] >> bitPos) & 1;
          } else {
            matrix[row][curCol] = 0;
          }
          bitIndex++;
        }
      }
      up = !up;
    }
  }

  /**
   * Check if position is reserved
   * @param {number} row
   * @param {number} col
   * @param {number} size
   * @returns {boolean}
   */
  function isReserved(row, col, size) {
    // Finder patterns and separators
    if (row < 9 && col < 9) return true;
    if (row < 9 && col >= size - 8) return true;
    if (row >= size - 8 && col < 9) return true;

    // Timing patterns
    if (row === 6 || col === 6) return true;

    return false;
  }

  /**
   * Add format information
   * @param {Array} matrix
   */
  function addFormatInfo(matrix) {
    const size = matrix.length;
    // Format bits for M level, mask 0 (simplified)
    const format = [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];

    // Around top-left finder
    for (let i = 0; i < 6; i++) {
      matrix[8][i] = format[i];
    }
    matrix[8][7] = format[6];
    matrix[8][8] = format[7];
    matrix[7][8] = format[8];
    for (let i = 9; i < 15; i++) {
      matrix[14 - i][8] = format[i];
    }

    // Around other finders
    for (let i = 0; i < 8; i++) {
      matrix[size - 1 - i][8] = format[i];
    }
    matrix[8][size - 8] = 1; // Dark module
    for (let i = 0; i < 7; i++) {
      matrix[8][size - 7 + i] = format[8 + i];
    }
  }

  /**
   * Apply mask pattern 0 (checkerboard)
   * @param {Array} matrix
   */
  function applyMask(matrix) {
    const size = matrix.length;
    for (let row = 0; row < size; row++) {
      for (let col = 0; col < size; col++) {
        if (isReserved(row, col, size)) continue;
        if ((row + col) % 2 === 0) {
          matrix[row][col] ^= 1;
        }
      }
    }
  }

  /**
   * Generate QR code matrix
   * @param {string} data
   * @returns {{matrix: Array, version: number, size: number}}
   */
  function generateMatrix(data) {
    const version = getVersion(data);
    const size = getSize(version);
    const matrix = createMatrix(size);

    // Add patterns
    addFinderPatterns(matrix);
    addTimingPatterns(matrix);
    addAlignmentPattern(matrix, version);

    // Encode and place data
    const dataCodewords = createDataCodewords(data, version);
    const [ecCount] = EC_TABLE[version];
    const ecCodewords = calculateEC(dataCodewords, ecCount);
    placeData(matrix, dataCodewords, ecCodewords);

    // Add format info and apply mask
    addFormatInfo(matrix);
    applyMask(matrix);

    return { matrix, version, size };
  }

  /**
   * Generate QR code as SVG (red on black)
   * @param {string} data - URL or text to encode
   * @param {Object} options - Styling options
   * @returns {string} SVG markup
   */
  function toSVG(data, options = {}) {
    const {
      moduleSize = 6,
      margin = 2,
      foreground = '#ff0000', // Red
      background = '#000000', // Black
      glow = true
    } = options;

    const { matrix, size } = generateMatrix(data);
    const svgSize = (size + margin * 2) * moduleSize;

    let paths = '';

    for (let row = 0; row < size; row++) {
      for (let col = 0; col < size; col++) {
        if (matrix[row][col] === 1) {
          const x = (col + margin) * moduleSize;
          const y = (row + margin) * moduleSize;
          paths += `M${x},${y}h${moduleSize}v${moduleSize}h-${moduleSize}z`;
        }
      }
    }

    const glowFilter = glow ? `
      <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2" result="blur"/>
          <feMerge>
            <feMergeNode in="blur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
    ` : '';

    const filterAttr = glow ? 'filter="url(#glow)"' : '';

    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${svgSize} ${svgSize}" width="${svgSize}" height="${svgSize}">
      ${glowFilter}
      <rect width="100%" height="100%" fill="${background}"/>
      <path d="${paths}" fill="${foreground}" ${filterAttr}/>
    </svg>`;
  }

  /**
   * Generate QR code and insert into DOM element
   * @param {HTMLElement} container - Container element
   * @param {string} data - URL or text to encode
   * @param {Object} options - Styling options
   */
  function render(container, data, options = {}) {
    const svg = toSVG(data, options);
    container.innerHTML = svg;
  }

  // Public API
  return {
    generateMatrix,
    toSVG,
    render
  };
})();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ScarbucksQR;
}
