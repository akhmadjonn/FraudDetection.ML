using FraudDetection.ML.Services;
using FraudDetection.ML.BackgroundJobs;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Application", "FraudDetection.ML")
    .CreateLogger();

builder.Services.AddSerilog();
// Register Services
builder.Services.AddSingleton<ClickHouseService>();
builder.Services.AddSingleton<FeatureEngineeringService>();
builder.Services.AddSingleton<IsolationForestService>();
builder.Services.AddSingleton<ClusteringService>();
builder.Services.AddSingleton<AnomalyAnalysisService>();
builder.Services.AddSingleton<NotificationService>();
builder.Services.AddHttpClient();

// Register Background Jobs
builder.Services.AddHostedService<ModelTrainingJob>();
builder.Services.AddHostedService<RealTimeScoringJob>();
builder.Services.AddHostedService<DailyAnalysisJob>();

var host = builder.Build();

// Get logger from DI container
var logger = host.Services.GetRequiredService<ILogger<Program>>();

// Create Models directory
var modelsDir = Path.Combine(AppContext.BaseDirectory, "Models");
Directory.CreateDirectory(modelsDir);

logger.LogInformation("═══════════════════════════════════════");
logger.LogInformation("Fraud Detection ML Service Starting...");
logger.LogInformation("═══════════════════════════════════════");
logger.LogInformation("Environment: {Environment}", builder.Environment.EnvironmentName);
logger.LogInformation("Models Directory: {ModelsDirectory}", modelsDir);


try
{
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.Information("Fraud Detection ML Service stopped");
    await Log.CloseAndFlushAsync();
}