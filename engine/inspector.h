#ifndef NETCHIMERA_INSPECTOR_H
#define NETCHIMERA_INSPECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

double CalculateShannonEntropy(const char* data, int length);
char* InspectHTTPPayload(const char* method, const char* path, const char* headers, const char* body);
void FreeInspectionResult(char* ptr);
const char* NetChimeraEngineVersion(void);

#ifdef __cplusplus
}
#endif

#endif
