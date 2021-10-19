@echo off

dotnet restore

dotnet build --no-restore -c Release

move /Y Panosen.Toolkit\bin\Release\Panosen.Toolkit.*.nupkg D:\LocalSavoryNuget\

pause