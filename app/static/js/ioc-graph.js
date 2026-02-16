/**
 * IOC Relationship Graph Visualization
 * Uses Cytoscape.js for interactive network graphs
 */
(function() {
    'use strict';

    class IOCGraph {
        constructor(containerId, iocId, options = {}) {
            this.container = document.getElementById(containerId);
            this.iocId = iocId;
            this.cy = null;
            this.currentDepth = 1;
            this.currentLayout = 'cose';
            this.options = {
                layout: 'cose',
                maxDepth: 3,
                ...options
            };
        }

        async init() {
            try {
                // Load initial graph data
                const data = await this.loadGraphData(this.currentDepth);

                // Check if we have any relationships
                if (data.nodes.length === 0) {
                    this.showEmptyState();
                    return;
                }

                // Initialize Cytoscape
                this.initializeCytoscape(data);
                this.setupEventHandlers();
                this.setupDarkModeObserver();
            } catch (error) {
                console.error('Error initializing graph:', error);
                this.showError('Failed to load graph. Please refresh the page.');
            }
        }

        async loadGraphData(depth) {
            const response = await fetch(`/iocs/${this.iocId}/graph-data?depth=${depth}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        }

        initializeCytoscape(data) {
            // Clear loading spinner
            this.container.innerHTML = '';

            this.cy = cytoscape({
                container: this.container,
                elements: [...data.nodes, ...data.edges],
                layout: {
                    name: this.currentLayout,
                    animate: true,
                    animationDuration: 500,
                    fit: true,
                    padding: 50,
                    // cose layout specific options
                    nodeRepulsion: 8000,
                    idealEdgeLength: 100,
                    edgeElasticity: 100,
                    nestingFactor: 5,
                    gravity: 80,
                    numIter: 1000,
                    initialTemp: 200,
                    coolingFactor: 0.95,
                    minTemp: 1.0
                },
                style: this.getStylesheet(),
                wheelSensitivity: 0.2,
                minZoom: 0.3,
                maxZoom: 3
            });
        }

        getStylesheet() {
            const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
            const theme = {
                nodeBorder: isDark ? '#404040' : '#dee2e6',
                nodeText: isDark ? '#e0e0e0' : '#212529',
                edgeColor: isDark ? '#6ea8fe' : '#0d6efd',
                edgeText: isDark ? '#a8a8a8' : '#6c757d',
                selectColor: '#0d6efd',
                hoverBorder: '#0d6efd'
            };

            return [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '80px',
                        'background-color': ele => this.getNodeColor(ele.data()),
                        'border-width': 2,
                        'border-color': theme.nodeBorder,
                        'width': ele => ele.data('is_center') ? 60 : 40,
                        'height': ele => ele.data('is_center') ? 60 : 40,
                        'color': theme.nodeText,
                        'font-size': ele => ele.data('is_center') ? '12px' : '10px',
                        'font-weight': ele => ele.data('is_center') ? 'bold' : 'normal',
                        'text-outline-width': 2,
                        'text-outline-color': isDark ? '#1a1a1a' : '#ffffff',
                        'overlay-padding': '6px',
                        'z-index': 10
                    }
                },
                {
                    selector: 'node:active',
                    style: {
                        'overlay-opacity': 0
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'label': 'data(label)',
                        'curve-style': 'bezier',
                        'target-arrow-shape': ele => ele.data('bidirectional') ? 'none' : 'triangle',
                        'line-color': theme.edgeColor,
                        'target-arrow-color': theme.edgeColor,
                        'width': 2,
                        'font-size': '9px',
                        'text-rotation': 'autorotate',
                        'text-margin-y': -10,
                        'color': theme.edgeText,
                        'text-outline-width': 2,
                        'text-outline-color': isDark ? '#1a1a1a' : '#ffffff',
                        'z-index': 5
                    }
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-width': 4,
                        'border-color': theme.selectColor
                    }
                },
                {
                    selector: 'node.hover',
                    style: {
                        'border-width': 4,
                        'border-color': theme.hoverBorder
                    }
                },
                {
                    selector: 'edge:selected',
                    style: {
                        'width': 3,
                        'line-color': theme.selectColor,
                        'target-arrow-color': theme.selectColor
                    }
                }
            ];
        }

        getNodeColor(nodeData) {
            // Color by severity
            const severityColors = {
                'Critical': '#212529',
                'High': '#dc3545',
                'Medium': '#ffc107',
                'Low': '#0dcaf0'
            };

            // If inactive, use gray
            if (!nodeData.is_active) {
                return '#6c757d';
            }

            return severityColors[nodeData.severity] || '#6c757d';
        }

        setupEventHandlers() {
            // Click to navigate
            this.cy.on('tap', 'node', (event) => {
                const node = event.target;
                const url = node.data('url');
                if (url && !node.data('is_center')) {
                    window.location.href = url;
                }
            });

            // Hover effects
            this.cy.on('mouseover', 'node', (event) => {
                const node = event.target;
                node.addClass('hover');
                this.container.style.cursor = node.data('is_center') ? 'default' : 'pointer';
            });

            this.cy.on('mouseout', 'node', (event) => {
                const node = event.target;
                node.removeClass('hover');
                this.container.style.cursor = 'default';
            });

            // Edge hover - show notes in tooltip
            this.cy.on('mouseover', 'edge', (event) => {
                const edge = event.target;
                const notes = edge.data('notes');
                if (notes) {
                    // You could add a tooltip here
                    console.log('Edge notes:', notes);
                }
            });
        }

        setupDarkModeObserver() {
            // Watch for dark mode changes
            const observer = new MutationObserver(() => {
                if (this.cy) {
                    this.applyStyles();
                }
            });

            observer.observe(document.documentElement, {
                attributes: true,
                attributeFilter: ['data-bs-theme']
            });
        }

        applyStyles() {
            if (this.cy) {
                this.cy.style(this.getStylesheet());
            }
        }

        async changeDepth(depth) {
            try {
                this.currentDepth = depth;
                this.showLoading();

                const data = await this.loadGraphData(depth);

                if (data.nodes.length === 0) {
                    this.showEmptyState();
                    return;
                }

                // Remove old elements and add new ones
                this.cy.elements().remove();
                this.cy.add([...data.nodes, ...data.edges]);

                // Re-run layout
                this.cy.layout({
                    name: this.currentLayout,
                    animate: true,
                    animationDuration: 500,
                    fit: true,
                    padding: 50
                }).run();
            } catch (error) {
                console.error('Error changing depth:', error);
                this.showError('Failed to load graph data.');
            }
        }

        changeLayout(layoutName) {
            this.currentLayout = layoutName;

            const layoutOptions = {
                name: layoutName,
                animate: true,
                animationDuration: 500,
                fit: true,
                padding: 50
            };

            // Add layout-specific options
            if (layoutName === 'cose') {
                layoutOptions.nodeRepulsion = 8000;
                layoutOptions.idealEdgeLength = 100;
                layoutOptions.edgeElasticity = 100;
            } else if (layoutName === 'breadthfirst') {
                layoutOptions.directed = true;
                layoutOptions.spacingFactor = 1.5;
            } else if (layoutName === 'circle') {
                layoutOptions.spacingFactor = 1.5;
            } else if (layoutName === 'grid') {
                layoutOptions.spacingFactor = 1.5;
            }

            this.cy.layout(layoutOptions).run();
        }

        fitToView() {
            if (this.cy) {
                this.cy.fit(null, 50);
            }
        }

        toggleFullscreen() {
            this.container.classList.toggle('fullscreen');

            // Give Cytoscape a moment to adjust to new size
            setTimeout(() => {
                if (this.cy) {
                    this.cy.resize();
                    this.cy.fit(null, 50);
                }
            }, 100);

            // Update button icon
            const btn = document.getElementById('graph-fullscreen');
            if (btn) {
                const icon = btn.querySelector('i');
                if (this.container.classList.contains('fullscreen')) {
                    icon.className = 'bi bi-fullscreen-exit';
                    btn.title = 'Exit fullscreen';
                } else {
                    icon.className = 'bi bi-arrows-fullscreen';
                    btn.title = 'Fullscreen';
                }
            }
        }

        showLoading() {
            this.container.innerHTML = `
                <div class="d-flex align-items-center justify-content-center h-100">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading graph...</span>
                    </div>
                </div>
            `;
        }

        showEmptyState() {
            this.container.innerHTML = `
                <div class="d-flex align-items-center justify-content-center h-100">
                    <p class="text-muted mb-0">No relationships found for this depth level.</p>
                </div>
            `;
        }

        showError(message) {
            this.container.innerHTML = `
                <div class="d-flex align-items-center justify-content-center h-100">
                    <div class="alert alert-danger mb-0" role="alert">
                        <i class="bi bi-exclamation-triangle"></i> ${message}
                    </div>
                </div>
            `;
        }
    }

    // Export to global scope
    window.IOCGraph = IOCGraph;

    // Initialize graph when DOM is ready
    document.addEventListener('DOMContentLoaded', () => {
        const graphContainer = document.getElementById('ioc-graph-container');
        if (graphContainer) {
            const iocId = graphContainer.dataset.iocId;
            window.iocGraph = new IOCGraph('ioc-graph-container', iocId);
            window.iocGraph.init();

            // Setup control event listeners
            const depthSelect = document.getElementById('graph-depth');
            if (depthSelect) {
                depthSelect.addEventListener('change', (e) => {
                    window.iocGraph.changeDepth(parseInt(e.target.value));
                });
            }

            const layoutSelect = document.getElementById('graph-layout');
            if (layoutSelect) {
                layoutSelect.addEventListener('change', (e) => {
                    window.iocGraph.changeLayout(e.target.value);
                });
            }

            const fitBtn = document.getElementById('graph-fit');
            if (fitBtn) {
                fitBtn.addEventListener('click', () => {
                    window.iocGraph.fitToView();
                });
            }

            const fullscreenBtn = document.getElementById('graph-fullscreen');
            if (fullscreenBtn) {
                fullscreenBtn.addEventListener('click', () => {
                    window.iocGraph.toggleFullscreen();
                });
            }
        }
    });
})();
