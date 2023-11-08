#include <clang-c/Index.h>
#include <stdio.h>

void DumpAST(CXCursor cursor, int level) {

    CXString cursorSpelling = clang_getCursorSpelling(cursor);



    // Get the cursor kind
    CXCursorKind kind = clang_getCursorKind(cursor);
    CXString kindSpelling = clang_getCursorKindSpelling(kind);

    // Type
    CXType type = clang_getCursorType(cursor);
    CXString typeSpelling = clang_getTypeSpelling(type);
    // CXTypeKind type_kind = clang_getTypeKind(type);
    CXString typeKindSpelling = clang_getTypeKindSpelling(type.kind);


    // Convert the cursor kind to a string for human-readable output
    const char* kind_str = clang_getCString(kindSpelling);
    const char* spelling_str = clang_getCString(cursorSpelling);
    const char* type_str = clang_getCString(typeSpelling);
    const char* type_kind_str = clang_getCString(typeKindSpelling);

    printf("%*s%s (%s) -- %s (%s)\n", level, "", spelling_str, kind_str, type_str, type_kind_str);

    clang_disposeString(cursorSpelling);
    clang_disposeString(kindSpelling);
    clang_disposeString(typeSpelling);

    clang_visitChildren(
        cursor,
        [](CXCursor c, CXCursor parent, CXClientData client_data) -> CXChildVisitResult {
            DumpAST(c, *static_cast<int*>(client_data) + 1);
            return CXChildVisit_Continue;
        },
        &level
    );
}

int main() {

    CXIndex index = clang_createIndex(0, 0);
    const char* source_filename = "/tmp/foo.cpp";
    const char* command_line_args[] = { "-std=c++11" }; // Add any necessary compiler flags

    getchar();
    CXTranslationUnit translationUnit = clang_parseTranslationUnit(
        index,
        source_filename,
        command_line_args,
        sizeof(command_line_args) / sizeof(command_line_args[0]),
        nullptr,
        0,
        CXTranslationUnit_None
    );


    if (!translationUnit) {
        // Handle parsing error
        return -1;
    }



    // Assuming you already have a valid translationUnit
    CXCursor cursor = clang_getTranslationUnitCursor(translationUnit);
    int level = 0;
    DumpAST(cursor, level);

    getchar();
    // Don't forget to clean up
    clang_disposeTranslationUnit(translationUnit);
    clang_disposeIndex(index);
    return 0;
}

