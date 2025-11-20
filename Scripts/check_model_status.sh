#!/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "ML Model Status Diagnostic"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "1. Checking if model files exist..."
echo "-------------------------------------------------------------------"
if [ -f "Models/isolation_forest.zip" ]; then
    echo "✅ Isolation Forest model: FOUND"
    ls -lh Models/isolation_forest.zip
else
    echo "❌ Isolation Forest model: NOT FOUND"
    echo "   Expected location: Models/isolation_forest.zip"
fi

if [ -f "Models/clustering_model.zip" ]; then
    echo "✅ Clustering model: FOUND"
    ls -lh Models/clustering_model.zip
else
    echo "❌ Clustering model: NOT FOUND"
    echo "   Expected location: Models/clustering_model.zip"
fi
echo ""

echo "2. Checking Models directory..."
echo "-------------------------------------------------------------------"
if [ -d "Models" ]; then
    echo "Models directory contents:"
    ls -lah Models/
else
    echo "⚠️  Models directory does not exist"
    echo "   Creating Models directory..."
    mkdir -p Models
    echo "✅ Models directory created"
fi
echo ""

echo "3. Checking application logs for training status..."
echo "-------------------------------------------------------------------"
echo "Recent log entries (if available):"
# Try to find log files
if [ -d "Logs" ]; then
    echo "Log files found:"
    ls -lht Logs/ | head -5
    echo ""
    echo "Last 20 lines from most recent log:"
    latest_log=$(ls -t Logs/*.log 2>/dev/null | head -1)
    if [ -n "$latest_log" ]; then
        tail -20 "$latest_log"
    else
        echo "No .log files found in Logs directory"
    fi
else
    echo "⚠️  No Logs directory found"
fi
echo ""

echo "4. Recommendations..."
echo "-------------------------------------------------------------------"
if [ ! -f "Models/isolation_forest.zip" ] || [ ! -f "Models/clustering_model.zip" ]; then
    echo "❌ ML Models are MISSING!"
    echo ""
    echo "This means:"
    echo "  • AnomalyScore will always be 0"
    echo "  • No fraud detection is happening"
    echo "  • Models need to be trained"
    echo ""
    echo "To train models:"
    echo "  1. Ensure you have at least 1000 sessions in ClickHouse"
    echo "  2. Start the application - ModelTrainingJob runs immediately"
    echo "  3. Check logs for: 'Model training completed successfully'"
    echo "  4. Verify models exist: ls -la Models/*.zip"
else
    echo "✅ Models exist - check application logs for scoring issues"
fi
echo ""

echo "═══════════════════════════════════════════════════════════════"
