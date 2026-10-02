import React, { useCallback, useEffect, useRef } from 'react';
import { groupColor } from './cytoscapeStyles';

const WIDTH = 180;
const HEIGHT = 120;

/**
 * Lightweight overview of the whole graph drawn from node positions, with a
 * viewport rectangle. Click anywhere to recentre the main graph there.
 *
 * Positions only change on layout, but the viewport changes on every pan/zoom,
 * so redraws are throttled with requestAnimationFrame.
 */
export default function GraphMinimap({ cy }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(null);

  const draw = useCallback(() => {
    frameRef.current = null;
    const canvas = canvasRef.current;
    if (!canvas || !cy || cy.destroyed()) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dark = document.documentElement.classList.contains('dark');
    ctx.clearRect(0, 0, WIDTH, HEIGHT);
    ctx.fillStyle = dark ? '#1e293b' : '#f1f5f9';
    ctx.fillRect(0, 0, WIDTH, HEIGHT);

    const elements = cy.elements();
    if (elements.length === 0) return;

    const bb = elements.boundingBox();
    const pad = Math.max(bb.w, bb.h) * 0.08 || 10;
    const spanX = bb.w + pad * 2 || 1;
    const spanY = bb.h + pad * 2 || 1;
    const scale = Math.min(WIDTH / spanX, HEIGHT / spanY);
    const offX = (WIDTH - spanX * scale) / 2;
    const offY = (HEIGHT - spanY * scale) / 2;
    const toX = (x) => offX + (x - (bb.x1 - pad)) * scale;
    const toY = (y) => offY + (y - (bb.y1 - pad)) * scale;

    ctx.strokeStyle = dark ? '#475569' : '#cbd5e1';
    ctx.lineWidth = 1;
    cy.edges().forEach((edge) => {
      const source = edge.source().position();
      const target = edge.target().position();
      ctx.beginPath();
      ctx.moveTo(toX(source.x), toY(source.y));
      ctx.lineTo(toX(target.x), toY(target.y));
      ctx.stroke();
    });

    cy.nodes().forEach((node) => {
      const position = node.position();
      const hidden = node.hasClass('hidden');
      ctx.globalAlpha = hidden ? 0.35 : 1;
      ctx.fillStyle = hidden ? (dark ? '#334155' : '#e2e8f0') : groupColor(node.data('group'));
      ctx.fillRect(toX(position.x) - 1.5, toY(position.y) - 1.5, 3, 3);
    });
    ctx.globalAlpha = 1;

    const extent = cy.extent();
    ctx.strokeStyle = dark ? '#60a5fa' : '#2563eb';
    ctx.lineWidth = 1;
    ctx.strokeRect(toX(extent.x1), toY(extent.y1), extent.w * scale, extent.h * scale);
  }, [cy]);

  const schedule = useCallback(() => {
    if (frameRef.current == null) {
      frameRef.current = requestAnimationFrame(draw);
    }
  }, [draw]);

  useEffect(() => {
    if (!cy || cy.destroyed()) return undefined;
    cy.on('render viewport resize layoutstop', schedule);
    schedule();
    return () => {
      cy.off('render viewport resize layoutstop', schedule);
      if (frameRef.current != null) {
        cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      }
    };
  }, [cy, schedule]);

  const handleClick = (event) => {
    if (!cy || cy.destroyed()) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const elements = cy.elements();
    if (elements.length === 0) return;

    const rect = canvas.getBoundingClientRect();
    const px = ((event.clientX - rect.left) / rect.width) * WIDTH;
    const py = ((event.clientY - rect.top) / rect.height) * HEIGHT;

    const bb = elements.boundingBox();
    const pad = Math.max(bb.w, bb.h) * 0.08 || 10;
    const spanX = bb.w + pad * 2 || 1;
    const spanY = bb.h + pad * 2 || 1;
    const scale = Math.min(WIDTH / spanX, HEIGHT / spanY);
    const offX = (WIDTH - spanX * scale) / 2;
    const offY = (HEIGHT - spanY * scale) / 2;
    const graphX = (px - offX) / scale + (bb.x1 - pad);
    const graphY = (py - offY) / scale + (bb.y1 - pad);

    cy.animate({ center: { x: graphX, y: graphY } }, { duration: 200 });
  };

  return (
    <canvas
      ref={canvasRef}
      width={WIDTH}
      height={HEIGHT}
      onClick={handleClick}
      className="absolute bottom-4 right-4 z-10 rounded border border-slate-200 dark:border-slate-700 shadow cursor-pointer bg-slate-100 dark:bg-slate-800"
      title="Minimap — click to recentre"
      aria-label="Graph minimap"
    />
  );
}
