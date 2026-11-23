// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { toPng, toJpeg } from 'html-to-image'
import jsPDF from 'jspdf'
import { safePixelRatio } from './exportSize'

const EXPORT_PADDING = 24
const EXPORT_PIXEL_RATIO = 2
const EXPORT_BACKGROUND = '#e0f2fe'
const PDF_JPEG_QUALITY = 0.85

// Export from an off-screen copy at full graph size, so pan and zoom don't affect it.
function cloneFullGraph(container: HTMLElement) {
  const svg = container.querySelector('svg[data-graph-width]') as SVGSVGElement | null
  if (!svg) return null
  const minX = Number(svg.dataset.graphMinX)
  const minY = Number(svg.dataset.graphMinY)
  const graphWidth = Number(svg.dataset.graphWidth)
  const graphHeight = Number(svg.dataset.graphHeight)
  if (!graphWidth || !graphHeight) return null

  const width = Math.ceil(graphWidth + 2 * EXPORT_PADDING)
  const height = Math.ceil(graphHeight + 2 * EXPORT_PADDING)

  const clone = svg.cloneNode(true) as SVGSVGElement
  const viewGroup = clone.querySelector('g')
  if (!viewGroup) return null
  viewGroup.setAttribute(
    'transform',
    `translate(${EXPORT_PADDING - minX}, ${EXPORT_PADDING - minY}) scale(1)`
  )
  clone.setAttribute('width', String(width))
  clone.setAttribute('height', String(height))
  clone.style.width = `${width}px`
  clone.style.height = `${height}px`

  // html-to-image copies computed styles, so off-screen positioning on the captured node would
  // export blank. It goes on a separate carrier element instead.
  const wrapper = document.createElement('div')
  wrapper.style.width = `${width}px`
  wrapper.style.height = `${height}px`
  wrapper.style.background = EXPORT_BACKGROUND
  wrapper.style.overflow = 'hidden'
  wrapper.appendChild(clone)

  const carrier = document.createElement('div')
  carrier.style.position = 'fixed'
  carrier.style.left = '-100000px'
  carrier.style.top = '0'
  carrier.appendChild(wrapper)
  document.body.appendChild(carrier)

  return { wrapper, width, height, cleanup: () => carrier.remove() }
}

// Attaching the link before clicking is needed for some browsers (Firefox).
export function download(href: string, fileName: string) {
  const link = document.createElement('a')
  link.download = fileName
  link.href = href
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

export async function exportElementAsPNG(el: HTMLElement, fileName = 'policy-visualizer.png') {
  const full = cloneFullGraph(el)
  if (!full) throw new Error('There is no diagram to export.')
  try {
    const dataUrl = await toPng(full.wrapper, {
      pixelRatio: safePixelRatio(full.width, full.height, EXPORT_PIXEL_RATIO),
      backgroundColor: EXPORT_BACKGROUND,
      width: full.width,
      height: full.height
    })
    download(dataUrl, fileName)
  } finally {
    full.cleanup()
  }
}

export async function exportElementAsPDF(el: HTMLElement, fileName = 'policy-visualizer.pdf') {
  const full = cloneFullGraph(el)
  if (!full) throw new Error('There is no diagram to export.')
  try {
    // JPEG keeps the image small; the background is a solid color, so quality loss is minimal.
    const dataUrl = await toJpeg(full.wrapper, {
      pixelRatio: safePixelRatio(full.width, full.height, EXPORT_PIXEL_RATIO),
      backgroundColor: EXPORT_BACKGROUND,
      quality: PDF_JPEG_QUALITY,
      width: full.width,
      height: full.height
    })
    const img = new Image()
    img.src = dataUrl
    await img.decode()
    const pdf = new jsPDF({
      orientation: img.width > img.height ? 'l' : 'p',
      unit: 'px',
      format: [img.width, img.height],
      compress: true
    })
    pdf.addImage(img, 'JPEG', 0, 0, img.width, img.height)
    pdf.save(fileName)
  } finally {
    full.cleanup()
  }
}
