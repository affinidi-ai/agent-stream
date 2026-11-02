import { ideSurfacesLinkingPipe } from '../usePipeSave';

const ideSurface = (
  id: string,
  name: string,
  memberPipeIds: Array<string | undefined>,
  status: string = 'enabled'
) => ({
  id,
  name,
  status,
  pipe_type: {
    type: 'ide_catalog',
    config: { members: memberPipeIds.map(pipe_id => ({ pipe_id })) },
  },
});

const llmSurface = (id: string, name: string) => ({
  id,
  name,
  status: 'enabled',
  pipe_type: { type: 'llm' },
});

describe('ideSurfacesLinkingPipe', () => {
  it('returns the names of IDE surfaces whose catalogue links the pipe', () => {
    const pipes = [
      llmSurface('llm-1', 'GPT surface'),
      ideSurface('ide-1', 'Team IDE', ['llm-1', 'llm-2']),
      ideSurface('ide-2', 'Other IDE', ['llm-2']),
    ];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual(['Team IDE']);
  });

  it('returns every linking IDE surface when multiple reference the pipe', () => {
    const pipes = [
      ideSurface('ide-1', 'IDE One', ['llm-1']),
      ideSurface('ide-2', 'IDE Two', ['llm-1', 'llm-3']),
    ];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual(['IDE One', 'IDE Two']);
  });

  it('returns an empty array when no IDE surface links the pipe', () => {
    const pipes = [llmSurface('llm-1', 'GPT surface'), ideSurface('ide-1', 'Team IDE', ['llm-2'])];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual([]);
  });

  it('ignores deleted IDE surfaces', () => {
    const pipes = [ideSurface('ide-1', 'Deleted IDE', ['llm-1'], 'deleted')];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual([]);
  });

  it('falls back to the id when the IDE surface has no name', () => {
    const pipes = [
      {
        id: 'ide-1',
        status: 'enabled',
        pipe_type: { type: 'ide_catalog', config: { members: [{ pipe_id: 'llm-1' }] } },
      },
    ];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual(['ide-1']);
  });

  it('ignores members with a blank pipe_id', () => {
    const pipes = [ideSurface('ide-1', 'Team IDE', [undefined, 'llm-2'])];
    expect(ideSurfacesLinkingPipe(pipes, 'llm-1')).toEqual([]);
  });

  it('returns an empty array for non-array input', () => {
    expect(ideSurfacesLinkingPipe(null, 'llm-1')).toEqual([]);
    expect(ideSurfacesLinkingPipe(undefined, 'llm-1')).toEqual([]);
  });
});
