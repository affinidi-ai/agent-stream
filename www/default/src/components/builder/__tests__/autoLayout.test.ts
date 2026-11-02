import { computeAutoLayout } from '../autoLayout';
import { nodesFromPipe } from '../elements/pipe/nodesFromPipe';

function juryWith(n: number) {
  return {
    jury: {
      enabled: true,
      mode: 'parallel',
      jurors: Array.from({ length: n }, (_, i) => ({
        name: `Juror ${i + 1}`,
        llm: { provider_type: 'openai', model: 'gpt-4o', endpoint_url: '/v1/chat' },
      })),
    },
  };
}

function serialJuryWith(n: number) {
  return {
    jury: {
      enabled: true,
      mode: 'serial',
      jurors: Array.from({ length: n }, (_, i) => ({
        name: `Juror ${i + 1}`,
        llm: { provider_type: 'openai', model: 'gpt-4o', endpoint_url: '/v1/chat' },
      })),
    },
  };
}

describe('computeAutoLayout — jurors', () => {
  it('lays jurors out in one horizontal row beneath the jury', () => {
    const { positions } = computeAutoLayout(nodesFromPipe(juryWith(3)));
    const jurors = positions.filter(p => p.id.startsWith('pipe-juror-'));
    expect(jurors).toHaveLength(3);
    const ys = new Set(jurors.map(p => p.y));
    expect(ys.size).toBe(1); // all on the same row
    expect([...ys][0]).toBeGreaterThan(0); // below the spine centre line
  });

  it('aligns at least one juror vertically under the jury node', () => {
    const { positions } = computeAutoLayout(nodesFromPipe(juryWith(4)));
    const juryX = positions.find(p => p.id === 'pipe-jury')!.x;
    const jurors = positions.filter(p => p.id.startsWith('pipe-juror-'));
    expect(jurors.some(p => p.x === juryX)).toBe(true);
  });

  it('keeps every juror inside the surface boundary', () => {
    for (const count of [1, 2, 5, 9]) {
      const { surfaceSize, positions } = computeAutoLayout(nodesFromPipe(juryWith(count)));
      const halfW = surfaceSize.w / 2;
      const halfH = surfaceSize.h / 2;
      const jurors = positions.filter(p => p.id.startsWith('pipe-juror-'));
      expect(jurors).toHaveLength(count);
      for (const p of jurors) {
        expect(Math.abs(p.x)).toBeLessThanOrEqual(halfW);
        expect(Math.abs(p.y)).toBeLessThanOrEqual(halfH);
      }
    }
  });

  it('stacks jurors in a vertical column under the jury in serial mode', () => {
    const { positions } = computeAutoLayout(nodesFromPipe(serialJuryWith(3)));
    const juryX = positions.find(p => p.id === 'pipe-jury')!.x;
    const jurors = positions.filter(p => p.id.startsWith('pipe-juror-')).sort((a, b) => a.y - b.y);
    expect(jurors).toHaveLength(3);
    // Every juror shares the jury's x (a single column)…
    expect(jurors.every(p => p.x === juryX)).toBe(true);
    // …and the y values strictly increase (each juror below the previous).
    expect(jurors[0].y).toBeGreaterThan(0);
    expect(jurors[1].y).toBeGreaterThan(jurors[0].y);
    expect(jurors[2].y).toBeGreaterThan(jurors[1].y);
  });

  it('keeps every serial juror inside the surface boundary', () => {
    for (const count of [1, 2, 5, 9]) {
      const { surfaceSize, positions } = computeAutoLayout(nodesFromPipe(serialJuryWith(count)));
      const halfW = surfaceSize.w / 2;
      const halfH = surfaceSize.h / 2;
      const jurors = positions.filter(p => p.id.startsWith('pipe-juror-'));
      expect(jurors).toHaveLength(count);
      for (const p of jurors) {
        expect(Math.abs(p.x)).toBeLessThanOrEqual(halfW);
        expect(Math.abs(p.y)).toBeLessThanOrEqual(halfH);
      }
    }
  });
});

function deciderWith(n: number) {
  return {
    decider: {
      enabled: true,
      system_prompt: 'route',
      llm: { provider_type: 'openai', model: 'gpt-4o-mini', endpoint_url: '/v1/chat' },
      candidates: Array.from({ length: n }, (_, i) => ({
        id: `c-${i}`,
        name: `Candidate ${i + 1}`,
        llm: { provider_type: 'openai', model: 'gpt-4o', endpoint_url: '/v1/chat' },
      })),
    },
  };
}

describe('computeAutoLayout — decider', () => {
  it('docks the decider directly beneath the LLM hero', () => {
    const { positions } = computeAutoLayout(nodesFromPipe(deciderWith(2)));
    const upstream = positions.find(p => p.id === 'pipe-upstream')!;
    const decider = positions.find(p => p.id === 'pipe-decider')!;
    expect(decider.x).toBe(upstream.x);
    expect(decider.y).toBeGreaterThan(upstream.y); // below the LLM hero
  });

  it('hugs the content asymmetrically — less space above the spine than below', () => {
    const { surfaceSize, positions } = computeAutoLayout(nodesFromPipe(deciderWith(2)));
    const halfH = surfaceSize.h / 2;
    const upstream = positions.find(p => p.id === 'pipe-upstream')!;
    const distToTop = upstream.y - -halfH;
    const distToBottom = halfH - upstream.y;
    expect(distToTop).toBeGreaterThan(0);
    expect(distToTop).toBeLessThan(distToBottom);
  });

  it('fans candidates across one horizontal row beneath the decider', () => {
    const { positions } = computeAutoLayout(nodesFromPipe(deciderWith(3)));
    const decider = positions.find(p => p.id === 'pipe-decider')!;
    const candidates = positions.filter(p => p.id.startsWith('pipe-candidate-'));
    expect(candidates).toHaveLength(3);
    const ys = new Set(candidates.map(p => p.y));
    expect(ys.size).toBe(1); // one row
    expect([...ys][0]).toBeGreaterThan(decider.y); // below the decider
    expect(candidates.some(p => p.x === decider.x)).toBe(true); // one under the decider
  });

  it('keeps every candidate inside the surface boundary', () => {
    for (const count of [1, 2, 5, 9]) {
      const { surfaceSize, positions } = computeAutoLayout(nodesFromPipe(deciderWith(count)));
      const halfW = surfaceSize.w / 2;
      const halfH = surfaceSize.h / 2;
      const candidates = positions.filter(p => p.id.startsWith('pipe-candidate-'));
      expect(candidates).toHaveLength(count);
      for (const p of candidates) {
        expect(Math.abs(p.x)).toBeLessThanOrEqual(halfW);
        expect(Math.abs(p.y)).toBeLessThanOrEqual(halfH);
      }
    }
  });
});
