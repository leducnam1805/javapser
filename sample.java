import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import java.util.HashSet;
import java.util.Set;

public class CodeConverter {

    public static void main(String[] args) {
        String sourceCode = """
                public class ActionController {

                    @RequestMapping(value = \"index\")
                    public String index(@ModelAttribute Form form) {
                        validate();
                    }

                    private void validate() {
                        doValidate();
                    }

                    private void doValidate() {
                        if CapUtil.hasError {
                            throw new AbcException(\"a.b.c\");
                        }
                    }
                }
                """;

        CompilationUnit cu = JavaParser.parse(sourceCode);
        Set<String> modifiedMethods = new HashSet<>();

        cu.accept(new ModifierVisitor<Void>() {
            @Override
            public MethodDeclaration visit(MethodDeclaration md, Void arg) {
                // Add BindingResult parameter if @RequestMapping is present
                if (md.getAnnotationByName("RequestMapping").isPresent()) {
                    if (md.getParameters().stream().noneMatch(p -> p.getType().asString().equals("BindingResult"))) {
                        md.addParameter("BindingResult", "result");
                    }

                    BlockStmt body = md.getBody().orElse(new BlockStmt());

                    // Add MessageHelper initialization
                    ObjectCreationExpr helperInit = new ObjectCreationExpr();
                    helperInit.setType("MessageHelper");
                    helperInit.addArgument("result");

                    body.addStatement(0, new ExpressionStmt(new com.github.javaparser.ast.expr.VariableDeclarationExpr(
                            new ClassOrInterfaceType(null, "MessageHelper"), "helper", helperInit)));

                    // Add if statement for error check
                    MethodCallExpr hasErrorCall = new MethodCallExpr("helper.hasError");
                    IfStmt ifStmt = new IfStmt(hasErrorCall, new ReturnStmt(new StringLiteralExpr("error")), null);
                    body.addStatement(ifStmt);

                    md.setBody(body);
                }

                // Check if method contains ThrowStmt with AbcException
                boolean containsThrowStmt = md.getBody()
                        .map(body -> body.findAll(ThrowStmt.class).stream()
                                .anyMatch(ts -> ts.getExpression().isObjectCreationExpr() &&
                                        ts.getExpression().asObjectCreationExpr().getType().getNameAsString().equals("AbcException")))
                        .orElse(false);

                if (containsThrowStmt) {
                    // Add MessageHelper parameter
                    if (md.getParameters().stream().noneMatch(p -> p.getType().asString().equals("MessageHelper"))) {
                        md.addParameter("MessageHelper", "helper");
                    }

                    // Track modified methods
                    modifiedMethods.add(md.getNameAsString());
                }

                // Check for methods with @ABC annotation and modify return statement
                if (md.getAnnotationByName("ABC").isPresent()) {
                    md.getBody().ifPresent(body -> {
                        body.findAll(ReturnStmt.class).forEach(returnStmt -> {
                            if (returnStmt.getExpression().isPresent() && returnStmt.getExpression().get() instanceof StringLiteralExpr) {
                                StringLiteralExpr returnValue = (StringLiteralExpr) returnStmt.getExpression().get();
                                returnValue.setString("forward:" + returnValue.getValue());
                            }
                        });
                    });
                }

                return super.visit(md, arg);
            }

            @Override
            public BlockStmt visit(ThrowStmt ts, Void arg) {
                if (ts.getExpression().isObjectCreationExpr()) {
                    ObjectCreationExpr exception = ts.getExpression().asObjectCreationExpr();
                    if (exception.getType().getNameAsString().equals("AbcException")) {
                        // Replace with helper.addGlobalError
                        MethodCallExpr addGlobalErrorCall = new MethodCallExpr("helper.addGlobalError");
                        exception.getArguments().forEach(addGlobalErrorCall::addArgument);

                        // Remove the throw statement and replace it with the helper call
                        return new BlockStmt().addStatement(new ExpressionStmt(addGlobalErrorCall));
                    }
                }
                return super.visit(ts, arg);
            }
        }, null);

        // Add MessageHelper parameter to methods that call modified methods
        cu.accept(new ModifierVisitor<Void>() {
            @Override
            public MethodDeclaration visit(MethodDeclaration md, Void arg) {
                md.getBody().ifPresent(body -> {
                    body.findAll(MethodCallExpr.class).forEach(mce -> {
                        if (modifiedMethods.contains(mce.getNameAsString())) {
                            if (md.getParameters().stream().noneMatch(p -> p.getType().asString().equals("MessageHelper"))) {
                                md.addParameter("MessageHelper", "helper");
                            }
                            mce.addArgument("helper");
                        }
                    });
                });
                return super.visit(md, arg);
            }
        }, null);

        System.out.println(cu.toString());
    }
}
