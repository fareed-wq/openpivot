import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  applyNodeChanges,
  applyEdgeChanges,
  Panel,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import SectionCard from './SectionCard';
import PivotButton from './PivotButton';

const TYPE_COLORS = {
  domain: '#3b82f6', // blue
  ip: '#10b981', // green
  asn: '#8b5cf6', // purple
  organization: '#f59e0b', // amber
  nameserver: '#6366f1', // indigo
  mail_server: '#ec4899', // pink
  certificate: '#14b8a6', // teal
  hostname: '#06b6d4', // cyan
};

const formatRelType = (type) => {
  const TYPE_LABELS = {
    resolves_to: 'Resolves to',
    uses_nameserver: 'Uses NS',
    uses_mail_server: 'Uses MX',
    presents_certificate: 'Presents Cert',
    contains_hostname: 'Contains Host',
    reverse_resolves_to: 'Reverse DNS',
    announced_by: 'Announced by',
    registered_to: 'Registered to'
  };
  return TYPE_LABELS[type] || type.replace(/_/g, ' ');
};

export default function InfrastructureGraph({ correlation, onPivot, isInvestigating }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNodeData, setSelectedNodeData] = useState(null);
  
  // Track if we've initialized layout for the current data
  const [isInitialized, setIsInitialized] = useState(false);

  // Derive counts
  const totalEntities = correlation?.entities?.length || 0;
  const totalRels = correlation?.relationships?.length || 0;

  const NODES_LIMIT = 100;
  const EDGES_LIMIT = 150;
  
  const isTruncated = totalEntities > NODES_LIMIT || totalRels > EDGES_LIMIT;

  // Initialize Data
  useMemo(() => {
    if (!correlation) return;

    // We only reset layout if the underlying data changes substantially, 
    // but ReactFlow takes care of rendering state.
    // So we just generate the initial nodes/edges array once per correlation input.
    let rawEntities = correlation.entities || [];
    let rawRels = correlation.relationships || [];

    if (rawEntities.length > NODES_LIMIT) rawEntities = rawEntities.slice(0, NODES_LIMIT);
    
    const survivingNodeIds = new Set(rawEntities.map(e => String(e.id)));
    rawRels = rawRels.filter(r => survivingNodeIds.has(String(r.source)) && survivingNodeIds.has(String(r.target)));
    
    if (rawRels.length > EDGES_LIMIT) rawRels = rawRels.slice(0, EDGES_LIMIT);

    // Simple Grid Layout
    const cols = Math.ceil(Math.sqrt(rawEntities.length));
    const spacingX = 250;
    const spacingY = 150;

    const newNodes = rawEntities.map((ent, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      
      const bgColor = TYPE_COLORS[ent.type] || '#9ca3af';

      return {
        id: String(ent.id),
        position: { x: col * spacingX, y: row * spacingY },
        data: { label: ent.value, type: ent.type, id: String(ent.id) },
        style: {
          background: bgColor,
          color: 'white',
          border: 'none',
          borderRadius: '8px',
          padding: '10px',
          fontSize: '12px',
          fontWeight: 'bold',
          width: 180,
          textAlign: 'center',
          wordBreak: 'break-word',
        }
      };
    });

    const newEdges = rawRels.map((rel, i) => ({
      id: `e-${rel.source}-${rel.target}-${i}`,
      source: String(rel.source),
      target: String(rel.target),
      label: formatRelType(rel.type),
      labelStyle: { fontSize: 10, fill: '#4b5563', fontWeight: 600 },
      labelBgStyle: { fill: '#ffffff', fillOpacity: 0.8 },
      style: { stroke: '#9ca3af', strokeWidth: 1.5 },
      animated: false
    }));

    setNodes(newNodes);
    setEdges(newEdges);
    setSelectedNodeData(null);
    setIsInitialized(true);
  }, [correlation]);

  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );
  
  const onEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    []
  );

  const onNodeClick = useCallback((event, node) => {
    setSelectedNodeData(node.data);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNodeData(null);
  }, []);

  if (!correlation) return null;

  if (totalEntities === 0 && totalRels === 0) {
    return (
      <SectionCard id="sec-graph" title="Interactive Infrastructure Graph" collapsible={true} defaultOpen={false}>
        <div className="text-gray-500 text-center py-8 bg-gray-50 rounded-lg border border-gray-200">
          No infrastructure graph data available.
        </div>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      id="sec-graph"
      title="Interactive Infrastructure Graph"
      collapsible={true}
      defaultOpen={false}
      subtitle={`${totalEntities} entities \u00B7 ${totalRels} relationships`}
    >
      <div className="w-full border border-gray-200 rounded-lg overflow-hidden bg-gray-50 relative" style={{ height: '500px' }}>
        {isTruncated && (
          <div className="absolute top-2 left-2 z-10 bg-yellow-50 border border-yellow-200 text-yellow-800 text-xs px-2 py-1 rounded shadow-sm">
            Warning: Graph truncated to {nodes.length} nodes and {edges.length} edges to maintain performance.
          </div>
        )}
        
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={4}
          attributionPosition="bottom-right"
        >
          <Background color="#ccc" gap={16} />
          <Controls />
          
          {selectedNodeData && (
            <Panel position="top-right" className="bg-white p-4 shadow-lg border border-gray-200 rounded-lg max-w-xs w-64 m-2 pointer-events-auto">
              <h4 className="font-bold text-gray-900 mb-1 border-b pb-1">Node Details</h4>
              <div className="text-sm space-y-2 mt-2">
                <div>
                  <span className="text-gray-500 block text-xs uppercase tracking-wider">Type</span>
                  <span className="font-medium text-gray-800 capitalize">{selectedNodeData.type}</span>
                </div>
                <div>
                  <span className="text-gray-500 block text-xs uppercase tracking-wider">Value</span>
                  <span className="font-mono text-gray-800 break-all">{selectedNodeData.label}</span>
                </div>
                
                {(selectedNodeData.type === 'domain' || selectedNodeData.type === 'ip') && (
                  <div className="pt-2 border-t mt-2">
                    <PivotButton 
                      target={selectedNodeData.label} 
                      onPivot={onPivot} 
                      disabled={isInvestigating} 
                    />
                  </div>
                )}
              </div>
            </Panel>
          )}
        </ReactFlow>
      </div>
    </SectionCard>
  );
}
