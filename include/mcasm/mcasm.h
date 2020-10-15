#include <stddef.h>

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_declspec_attribute
#define __has_declspec_attribute(x) 0
#endif

#if defined(_MSC_VER) || __has_declspec_attribute(dllexport)
// Defined by the build system This should only be defined by the build system
// which generates the library. Users of the library should NOT define this.
#ifdef MC_USE_DLL_EXPORTS
#define MC_EXPORT _declspec(dllexport)
#else
#define MC_EXPORT
#endif // MC_USE_DLL_EXPORTS
#elif defined(__GNUC__) || __has_attribute(visibility)
#define MC_EXPORT __attribute__((visibility("default")))
#else
#define MC_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MCAssemblerImp* MCAssemblerRef;

typedef enum MCError {
  MC_ERROR_SUCCESS,
  MC_ERROR_FAILED_WITH_DIAGNOSTICS,
  MC_ERROR_UNSUPPORTED_TARGET,
  MC_ERROR_FAILED,
  MC_ERROR_INVALID_OPTION,
  MC_ERROR_INVALID_OPTION_VALUE,
} MCError;

typedef enum MCOption {
  MC_OPTION_X86_SYNTAX,
  MC_OPTION_PRETTY_PRINT,
} MCOption;

typedef enum MCX86Syntax {
  MC_X86_SYNTAX_ATT,
  MC_X86_SYNTAX_INTEL,
} MCX86Syntax;

/**
 *@brief Obtains the default target triple for the system.
 */
MC_EXPORT const char* MCDefaultTriple(void);

/**
 *@brief Obtains a string description for an error code.
 */
MC_EXPORT const char* MCErrorToString(MCError err);

/**
 *@brief Obtains the version of the library.
 */
MC_EXPORT void MCLibraryVersion(unsigned* Major, unsigned* Minor,
                                unsigned* Patch);

/**
 *@brief Obtains the version of LLVM used by this library
 */
MC_EXPORT void MCLLVMVersion(unsigned* Major, unsigned* Minor, unsigned* Patch);

/**
 *@brief Creates a new assembler.
 *
 *@param TargetTriple The target triple to assemble for.
 *@param OutAssembler The created assembler object upon success.
 *@return SUCCESS if the assembler was created. An appropriate error
 *        otherwise.
 */
MC_EXPORT MCError MCAssemblerCreate(const char* TargetTriple,
                                    MCAssemblerRef* OutAssembler);

/**
 *@brief Assembles an input string to a JSON document that contains a series
 *       of events. For example, there is an "instruction" event for each
 *       instruction parsed that contains the instruction's encoding, the
 *       details of the operands, and any fixups required.
 *
 *@param Assembler The assembler object.
 *@param Input The input assembly string.
 *@param OutJSON The resulting JSON, if this function returns SUCCESS or
 *               FAILED_WITH_DIAGNOSTICS. This memory is owned by the
 *               assembler and does not to be freed (but also is only valid
 *               until the next call to the assembler).
 *@return SUCCESS if the code assembled without errors.
 *        FAILED_WITH_DIAGNOSTICS if the code had diagnosed errors, which will
 *        be present in the output JSON.
 *        An approporiate error otherwise.
 */
MC_EXPORT MCError MCAssemblerAssembleToJSON(MCAssemblerRef Assembler,
                                            const char* Input,
                                            char const** OutJSON);

/**
 *@brief Sets an option on the assembler object.
 *
 *@param Assembler The assembler object.
 *@param Opt The option to alter.
 *@param Value The new value for the option.
 *@return SUCCESS if the option and its value were valid. Otherwise either
 *        INVALID_OPTION or INVALID_OPTION_VALUE.
 */
MC_EXPORT MCError MCAssemblerSetOption(MCAssemblerRef Assembler, MCOption Opt,
                                       size_t Value);

/**
 *@brief Destroys the assembler and frees its resources.
 */
MC_EXPORT void MCAssemblerDestroy(MCAssemblerRef Assembler);

#ifdef __cplusplus
}
#endif
