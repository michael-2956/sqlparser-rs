// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::ast::{CommentObject, Statement, DataType, Expr, Function, ObjectName, UnaryOperator, Ident, BinaryOperator, JsonOperator};
use crate::dialect::Dialect;
use crate::keywords::Keyword;
use crate::parser::{Parser, ParserError};
use crate::parser_err;
use crate::tokenizer::Token;

#[derive(Debug)]
pub struct PostgreSqlDialect {}

impl PostgreSqlDialect {
    /// Operation precedence reference: https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-PRECEDENCE-TABLE
    const BASE_PREC: u8 = 0;
    /// .       table/column name separator
    const NAME_SEPARATOR_PREC: u8 = 23;
    /// ::	    PostgreSQL-style typecast
    const DOUBLE_COLON_TYPECAST_PREC: u8 = 22;
    /// [ ]	    array element selection
    const BRACKET_ARRAY_ELEMENT_PREC: u8 = 21;
    /// + -	    unary plus, unary minus. It is supposed that parse_prefix parses
    const UNARY_PLUS_MINUS_PREC: u8 = 20;
    /// ^	    exponentiation
    const EXPONENTIATION_PREC: u8 = 19;
    /// * / %   multiplication, division, modulo
    const MULT_DIV_MOD_PREC: u8 = 18;
    /// + -	    addition, subtraction
    const BINARY_ADD_SUB_PREC: u8 = 17;
    /// (any other operator)	         all other native and user-defined operators
    const OTHER_OPERATOR_PREC: u8 = 16;
    /// BETWEEN IN LIKE ILIKE SIMILAR	 range containment, set membership, string matching
    const BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC: u8 = 15;
    /// < > = <= >= <>	 	             comparison operators
    const CMP_PREC: u8 = 14;
    /// IS ISNULL NOTNULL	 	         IS TRUE, IS FALSE, IS NULL, IS DISTINCT FROM, etc.
    const IS_PREC: u8 = 13;
    /// NOT	    logical negation
    const NOT_PREC: u8 = 12;
    /// AND	    logical conjunction
    const AND_PREC: u8 = 11;
    /// OR	    logical disjunction
    const OR_PREC: u8 = 10;

    fn parse_not(parser: &mut Parser) -> Result<Expr, ParserError> {
        match parser.peek_token().token {
            Token::Word(w) => match w.keyword {
                Keyword::EXISTS => {
                    let negated = true;
                    let _ = parser.parse_keyword(Keyword::EXISTS);
                    parser.parse_exists_expr(negated)
                }
                _ => Ok(Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr: Box::new(parser.parse_subexpr(Self::NOT_PREC)?),
                }),
            },
            _ => Ok(Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: Box::new(parser.parse_subexpr(Self::NOT_PREC)?),
            }),
        }
    }

    fn parse_position_expr(parser: &mut Parser) -> Result<Expr, ParserError> {
        // PARSE SELECT POSITION('@' in field)
        parser.expect_token(&Token::LParen)?;

        // Parse the subexpr till the IN keyword
        let expr = parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC)?;
        if parser.parse_keyword(Keyword::IN) {
            let from = parser.parse_expr()?;
            parser.expect_token(&Token::RParen)?;
            Ok(Expr::Position {
                expr: Box::new(expr),
                r#in: Box::new(from),
            })
        } else {
            parser_err!("Position function must include IN keyword".to_string())
        }
    }

    fn parse_between(parser: &mut Parser, expr: Expr, negated: bool) -> Result<Expr, ParserError> {
        // Stop parsing subexpressions for <low> and <high> on tokens with
        // precedence lower than that of `BETWEEN`, such as `AND`, `IS`, etc.
        let low = parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC)?;
        parser.expect_keyword(Keyword::AND)?;
        let high = parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC)?;
        Ok(Expr::Between {
            expr: Box::new(expr),
            negated,
            low: Box::new(low),
            high: Box::new(high),
        })
    }
}

// Returns a successful result if the optional expression is some
macro_rules! return_some_ok_if_some {
    ($e:expr) => {{
        if let Some(v) = $e {
            return Some(Ok(v));
        }
    }};
}

// Returns a Some(Err) if the Result is Err
macro_rules! some_q {
    ($e:expr) => {{
        match $e {
            Ok(val) => val,
            Err(err) => return Some(Err(err)),
        }
    }};
}

impl Dialect for PostgreSqlDialect {
    fn is_identifier_start(&self, ch: char) -> bool {
        // See https://www.postgresql.org/docs/11/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS
        // We don't yet support identifiers beginning with "letters with
        // diacritical marks and non-Latin letters"
        ('a'..='z').contains(&ch) || ('A'..='Z').contains(&ch) || ch == '_'
    }

    fn is_identifier_part(&self, ch: char) -> bool {
        ('a'..='z').contains(&ch)
            || ('A'..='Z').contains(&ch)
            || ('0'..='9').contains(&ch)
            || ch == '$'
            || ch == '_'
    }

    /// Get the precedence of the next token
    fn get_next_precedence(&self, parser: &Parser) -> Option<Result<u8, ParserError>> {
        // allow the dialect to override precedence logic

        let token = parser.peek_token();
        Some(Ok(match token.token {
            Token::Period => Self::NAME_SEPARATOR_PREC,
            Token::DoubleColon => Self::DOUBLE_COLON_TYPECAST_PREC,
            Token::LBracket => Self::BRACKET_ARRAY_ELEMENT_PREC,
            Token::RBracket => Self::BASE_PREC,
            Token::Caret => Self::EXPONENTIATION_PREC,
            Token::Mul | Token::Div | Token::Mod => Self::MULT_DIV_MOD_PREC,
            Token::Plus | Token::Minus => Self::BINARY_ADD_SUB_PREC,

            Token::Word(w) if w.keyword == Keyword::BETWEEN => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
            Token::Word(w) if w.keyword == Keyword::IN => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
            Token::Word(w) if w.keyword == Keyword::LIKE => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
            Token::Word(w) if w.keyword == Keyword::ILIKE => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
            Token::Word(w) if w.keyword == Keyword::SIMILAR => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,

            Token::Eq
            | Token::Lt
            | Token::LtEq
            | Token::Neq
            | Token::Gt
            | Token::GtEq => Self::CMP_PREC,

            Token::Word(w) if w.keyword == Keyword::IS => Self::IS_PREC,

            Token::Word(w) if w.keyword == Keyword::NOT => match parser.peek_nth_token(1).token {
                // The precedence of NOT varies depending on keyword that
                // follows it. If it is followed by IN, BETWEEN, or LIKE,
                // it takes on the precedence of those tokens. Otherwise it
                // is not an infix operator, and therefore has its usual
                // precedence.
                Token::Word(w) if w.keyword == Keyword::BETWEEN => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
                Token::Word(w) if w.keyword == Keyword::IN => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
                Token::Word(w) if w.keyword == Keyword::LIKE => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
                Token::Word(w) if w.keyword == Keyword::ILIKE => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
                Token::Word(w) if w.keyword == Keyword::SIMILAR => Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC,
                _ => Self::NOT_PREC,
            },
            Token::Word(w) if w.keyword == Keyword::AND => Self::AND_PREC,
            Token::Word(w) if w.keyword == Keyword::OR => Self::OR_PREC,
            
            Token::Word(w) if w.keyword == Keyword::XOR => Self::OTHER_OPERATOR_PREC,
            Token::Word(w) if w.keyword == Keyword::AT => Self::OTHER_OPERATOR_PREC,
            Token::Word(w) if w.keyword == Keyword::OPERATOR => Self::OTHER_OPERATOR_PREC,
            Token::DoubleEq
            | Token::Tilde
            | Token::TildeAsterisk
            | Token::ExclamationMarkTilde
            | Token::ExclamationMarkTildeAsterisk
            | Token::Spaceship => Self::OTHER_OPERATOR_PREC,
            Token::Pipe => Self::OTHER_OPERATOR_PREC,
            Token::Sharp | Token::ShiftRight | Token::ShiftLeft => Self::OTHER_OPERATOR_PREC,
            Token::Ampersand => Self::OTHER_OPERATOR_PREC,
            Token::StringConcat => Self::OTHER_OPERATOR_PREC,
            Token::Colon
            | Token::ExclamationMark
            | Token::LongArrow
            | Token::Arrow
            | Token::HashArrow
            | Token::HashLongArrow
            | Token::AtArrow
            | Token::ArrowAt
            | Token::HashMinus
            | Token::AtQuestion
            | Token::AtAt => Self::OTHER_OPERATOR_PREC,
            _ => Self::BASE_PREC,
        }))
    }

    fn parse_prefix(&self, parser: &mut Parser) -> Option<Result<crate::ast::Expr, ParserError>> {
        // PostgreSQL allows any string literal to be preceded by a type name, indicating that the
        // string literal represents a literal of that type. Some examples:
        //
        //      DATE '2020-05-20'
        //      TIMESTAMP WITH TIME ZONE '2020-05-20 7:43:54'
        //      BOOL 'true'
        //
        // The first two are standard SQL, while the latter is a PostgreSQL extension. Complicating
        // matters is the fact that INTERVAL string literals may optionally be followed by special
        // keywords, e.g.:
        //
        //      INTERVAL '7' DAY
        //
        // Note also that naively `SELECT date` looks like a syntax error because the `date` type
        // name is not followed by a string literal, but in fact in PostgreSQL it is a valid
        // expression that should parse as the column name "date".
        return_some_ok_if_some!(parser.maybe_parse(|parser| {
            match parser.parse_data_type()? {
                DataType::Interval => parser.parse_interval(),
                // PostgreSQL allows almost any identifier to be used as custom data type name,
                // and we support that in `parse_data_type()`. But unlike Postgres we don't
                // have a list of globally reserved keywords (since they vary across dialects),
                // so given `NOT 'a' LIKE 'b'`, we'd accept `NOT` as a possible custom data type
                // name, resulting in `NOT 'a'` being recognized as a `TypedString` instead of
                // an unary negation `NOT ('a' LIKE 'b')`. To solve this, we don't accept the
                // `type 'string'` syntax for the custom data types at all.
                DataType::Custom(..) => parser_err!("dummy"),
                data_type => Ok(Expr::TypedString {
                    data_type,
                    value: parser.parse_literal_string()?,
                }),
            }
        }));

        let next_token = parser.next_token();
        let expr = some_q!(match next_token.token {
            Token::Word(w) => match w.keyword {
                Keyword::TRUE | Keyword::FALSE | Keyword::NULL => {
                    parser.prev_token();
                    Ok(Expr::Value(some_q!(parser.parse_value())))
                }
                Keyword::CURRENT_CATALOG
                | Keyword::CURRENT_USER
                | Keyword::SESSION_USER
                | Keyword::USER =>
                {
                    Ok(Expr::Function(Function {
                        name: ObjectName(vec![w.to_ident()]),
                        args: vec![],
                        over: None,
                        distinct: false,
                        special: true,
                    }))
                }
                Keyword::CURRENT_TIMESTAMP
                | Keyword::CURRENT_TIME
                | Keyword::CURRENT_DATE
                | Keyword::LOCALTIME
                | Keyword::LOCALTIMESTAMP => {
                    parser.parse_time_functions(ObjectName(vec![w.to_ident()]))
                }
                Keyword::CASE => parser.parse_case_expr(),
                Keyword::CAST => parser.parse_cast_expr(),
                Keyword::TRY_CAST => parser.parse_try_cast_expr(),
                Keyword::SAFE_CAST => parser.parse_safe_cast_expr(),
                Keyword::EXISTS => parser.parse_exists_expr(false),
                Keyword::EXTRACT => parser.parse_extract_expr(),
                Keyword::CEIL => parser.parse_ceil_floor_expr(true),
                Keyword::FLOOR => parser.parse_ceil_floor_expr(false),
                Keyword::POSITION => Self::parse_position_expr(parser),
                Keyword::SUBSTRING => parser.parse_substring_expr(),
                Keyword::OVERLAY => parser.parse_overlay_expr(),
                Keyword::TRIM => parser.parse_trim_expr(),
                Keyword::INTERVAL => parser.parse_interval(),
                Keyword::LISTAGG => parser.parse_listagg_expr(),
                // Treat ARRAY[1,2,3] as an array [1,2,3], otherwise try as subquery or a function call
                Keyword::ARRAY if parser.peek_token() == Token::LBracket => {
                    some_q!(parser.expect_token(&Token::LBracket));
                    parser.parse_array_expr(true)
                }
                Keyword::ARRAY
                    if parser.peek_token() == Token::LParen =>
                {
                    some_q!(parser.expect_token(&Token::LParen));
                    parser.parse_array_subquery()
                }
                Keyword::ARRAY_AGG => parser.parse_array_agg_expr(),
                Keyword::NOT => Self::parse_not(parser),
                // Here `w` is a word, check if it's a part of a multi-part
                // identifier, a function call, or a simple identifier:
                _ => match parser.peek_token().token {
                    Token::LParen | Token::Period => {
                        let mut id_parts: Vec<Ident> = vec![w.to_ident()];
                        while parser.consume_token(&Token::Period) {
                            let next_token = parser.next_token();
                            match next_token.token {
                                Token::Word(w) => id_parts.push(w.to_ident()),
                                _ => {
                                    return Some(parser.expected("an identifier or a '*' after '.'", next_token));
                                }
                            }
                        }

                        if parser.consume_token(&Token::LParen) {
                            parser.prev_token();
                            parser.parse_function(ObjectName(id_parts))
                        } else {
                            Ok(Expr::CompoundIdentifier(id_parts))
                        }
                    }
                    // string introducer https://dev.mysql.com/doc/refman/8.0/en/charset-introducer.html
                    Token::SingleQuotedString(_)
                    | Token::DoubleQuotedString(_)
                    | Token::HexStringLiteral(_)
                        if w.value.starts_with('_') =>
                    {
                        Ok(Expr::IntroducedString {
                            introducer: w.value,
                            value: some_q!(parser.parse_introduced_string_value()),
                        })
                    }
                    _ => Ok(Expr::Identifier(w.to_ident())),
                },
            }, // End of Token::Word
            // array `[1, 2, 3]`
            Token::LBracket => parser.parse_array_expr(false),
            tok @ Token::Minus | tok @ Token::Plus => {
                let op = if tok == Token::Plus {
                    UnaryOperator::Plus
                } else {
                    UnaryOperator::Minus
                };
                Ok(Expr::UnaryOp {
                    op,
                    expr: Box::new(some_q!(parser.parse_subexpr(Self::UNARY_PLUS_MINUS_PREC))),
                })
            }
            tok @ Token::DoubleExclamationMark
            | tok @ Token::PGSquareRoot
            | tok @ Token::PGCubeRoot
            | tok @ Token::AtSign
            | tok @ Token::Tilde => {
                let op = match tok {
                    Token::DoubleExclamationMark => UnaryOperator::PGPrefixFactorial,
                    Token::PGSquareRoot => UnaryOperator::PGSquareRoot,
                    Token::PGCubeRoot => UnaryOperator::PGCubeRoot,
                    Token::AtSign => UnaryOperator::PGAbs,
                    Token::Tilde => UnaryOperator::PGBitwiseNot,
                    _ => unreachable!(),
                };
                Ok(Expr::UnaryOp {
                    op,
                    expr: Box::new(some_q!(parser.parse_subexpr(Self::OTHER_OPERATOR_PREC))),
                })
            }
            Token::EscapedStringLiteral(_) =>
            {
                parser.prev_token();
                Ok(Expr::Value(some_q!(parser.parse_value())))
            }
            Token::Number(_, _)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::HexStringLiteral(_) => {
                parser.prev_token();
                Ok(Expr::Value(some_q!(parser.parse_value())))
            }
            Token::LParen => {
                let expr =
                    if parser.parse_keyword(Keyword::SELECT) || parser.parse_keyword(Keyword::WITH) {
                        parser.prev_token();
                        Expr::Subquery(Box::new(some_q!(parser.parse_query())))
                    } else {
                        let exprs = some_q!(parser.parse_comma_separated(Parser::parse_expr));
                        match exprs.len() {
                            0 => unreachable!(), // parse_comma_separated ensures 1 or more
                            1 => Expr::Nested(Box::new(exprs.into_iter().next().unwrap())),
                            _ => Expr::Tuple(exprs),
                        }
                    };
                some_q!(parser.expect_token(&Token::RParen));
                if !parser.consume_token(&Token::Period) {
                    Ok(expr)
                } else {
                    let tok = parser.next_token();
                    let key = match tok.token {
                        Token::Word(word) => word.to_ident(),
                        _ => return Some(parser_err!(format!("Expected identifier, found: {tok}"))),
                    };
                    Ok(Expr::CompositeAccess {
                        expr: Box::new(expr),
                        key,
                    })
                }
            }
            Token::Placeholder(_) | Token::Colon => {
                parser.prev_token();
                Ok(Expr::Value(some_q!(parser.parse_value())))
            }
            _ => parser.expected("an expression:", next_token),
        });

        Some(if parser.parse_keyword(Keyword::COLLATE) {
            Ok(Expr::Collate {
                expr: Box::new(expr),
                collation: some_q!(parser.parse_object_name()),
            })
        } else {
            Ok(expr)
        })
    }

    /// Parse an operator following an expression
    fn parse_infix(&self, parser: &mut Parser, expr: &Expr, precedence: u8) -> Option<Result<Expr, ParserError>> {
        let tok = parser.next_token();

        let regular_binary_operator = match &tok.token {
            Token::Spaceship => Some(BinaryOperator::Spaceship),
            Token::DoubleEq => Some(BinaryOperator::Eq),
            Token::Eq => Some(BinaryOperator::Eq),
            Token::Neq => Some(BinaryOperator::NotEq),
            Token::Gt => Some(BinaryOperator::Gt),
            Token::GtEq => Some(BinaryOperator::GtEq),
            Token::Lt => Some(BinaryOperator::Lt),
            Token::LtEq => Some(BinaryOperator::LtEq),
            Token::Plus => Some(BinaryOperator::Plus),
            Token::Minus => Some(BinaryOperator::Minus),
            Token::Mul => Some(BinaryOperator::Multiply),
            Token::Mod => Some(BinaryOperator::Modulo),
            Token::StringConcat => Some(BinaryOperator::StringConcat),
            Token::Pipe => Some(BinaryOperator::BitwiseOr),
            Token::Caret => Some(BinaryOperator::PGExp),
            Token::Ampersand => Some(BinaryOperator::BitwiseAnd),
            Token::Div => Some(BinaryOperator::Divide),
            Token::ShiftLeft => Some(BinaryOperator::PGBitwiseShiftLeft),
            Token::ShiftRight => Some(BinaryOperator::PGBitwiseShiftRight),
            Token::Sharp => Some(BinaryOperator::PGBitwiseXor),
            Token::Tilde => Some(BinaryOperator::PGRegexMatch),
            Token::TildeAsterisk => Some(BinaryOperator::PGRegexIMatch),
            Token::ExclamationMarkTilde => Some(BinaryOperator::PGRegexNotMatch),
            Token::ExclamationMarkTildeAsterisk => Some(BinaryOperator::PGRegexNotIMatch),
            Token::Word(w) => match w.keyword {
                Keyword::AND => Some(BinaryOperator::And),
                Keyword::OR => Some(BinaryOperator::Or),
                Keyword::XOR => Some(BinaryOperator::Xor),
                Keyword::OPERATOR => {
                    some_q!(parser.expect_token(&Token::LParen));
                    // there are special rules for operator names in
                    // postgres so we can not use 'parse_object'
                    // or similar.
                    // See https://www.postgresql.org/docs/current/sql-createoperator.html
                    let mut idents = vec![];
                    loop {
                        idents.push(parser.next_token().to_string());
                        if !parser.consume_token(&Token::Period) {
                            break;
                        }
                    }
                    some_q!(parser.expect_token(&Token::RParen));
                    Some(BinaryOperator::PGCustomBinaryOperator(idents))
                }
                _ => None,
            },
            _ => None,
        };

        Some(if let Some(op) = regular_binary_operator {
            if let Some(keyword) = parser.parse_one_of_keywords(&[Keyword::ANY, Keyword::ALL]) {
                some_q!(parser.expect_token(&Token::LParen));
                let right = some_q!(parser.parse_subexpr(precedence));
                some_q!(parser.expect_token(&Token::RParen));

                let right = match keyword {
                    Keyword::ALL => Box::new(Expr::AllOp(Box::new(right))),
                    Keyword::ANY => Box::new(Expr::AnyOp(Box::new(right))),
                    _ => unreachable!(),
                };

                Ok(Expr::BinaryOp {
                    left: Box::new(expr.to_owned()),
                    op,
                    right,
                })
            } else {
                Ok(Expr::BinaryOp {
                    left: Box::new(expr.to_owned()),
                    op,
                    right: Box::new(some_q!(parser.parse_subexpr(precedence))),
                })
            }
        } else if let Token::Word(w) = &tok.token {
            match w.keyword {
                Keyword::IS => {
                    if parser.parse_keyword(Keyword::NULL) {
                        Ok(Expr::IsNull(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::NOT, Keyword::NULL]) {
                        Ok(Expr::IsNotNull(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::TRUE]) {
                        Ok(Expr::IsTrue(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::NOT, Keyword::TRUE]) {
                        Ok(Expr::IsNotTrue(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::FALSE]) {
                        Ok(Expr::IsFalse(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::NOT, Keyword::FALSE]) {
                        Ok(Expr::IsNotFalse(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::UNKNOWN]) {
                        Ok(Expr::IsUnknown(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::NOT, Keyword::UNKNOWN]) {
                        Ok(Expr::IsNotUnknown(Box::new(expr.to_owned())))
                    } else if parser.parse_keywords(&[Keyword::DISTINCT, Keyword::FROM]) {
                        let expr2 = some_q!(parser.parse_expr());
                        Ok(Expr::IsDistinctFrom(Box::new(expr.to_owned()), Box::new(expr2)))
                    } else if parser.parse_keywords(&[Keyword::NOT, Keyword::DISTINCT, Keyword::FROM])
                    {
                        let expr2 = some_q!(parser.parse_expr());
                        Ok(Expr::IsNotDistinctFrom(Box::new(expr.to_owned()), Box::new(expr2)))
                    } else {
                        parser.expected(
                            "[NOT] NULL or TRUE|FALSE or [NOT] DISTINCT FROM after IS",
                            parser.peek_token(),
                        )
                    }
                }
                Keyword::AT => {
                    // if parser.parse_keyword(Keyword::TIME) {
                    //     parser.expect_keyword(Keyword::ZONE)?;
                    if parser.parse_keywords(&[Keyword::TIME, Keyword::ZONE]) {
                        let time_zone = parser.next_token();
                        match time_zone.token {
                            Token::SingleQuotedString(time_zone) => {
                                log::trace!("Peek token: {:?}", parser.peek_token());
                                Ok(Expr::AtTimeZone {
                                    timestamp: Box::new(expr.to_owned()),
                                    time_zone,
                                })
                            }
                            _ => parser.expected(
                                "Expected Token::SingleQuotedString after AT TIME ZONE",
                                time_zone,
                            ),
                        }
                    } else {
                        parser.expected("Expected Token::Word after AT", tok)
                    }
                }
                Keyword::NOT
                | Keyword::IN
                | Keyword::BETWEEN
                | Keyword::LIKE
                | Keyword::ILIKE
                | Keyword::SIMILAR => {
                    parser.prev_token();
                    let negated = parser.parse_keyword(Keyword::NOT);
                    if parser.parse_keyword(Keyword::IN) {
                        parser.parse_in(expr.to_owned(), negated)
                    } else if parser.parse_keyword(Keyword::BETWEEN) {
                        Self::parse_between(parser, expr.to_owned(), negated)
                    } else if parser.parse_keyword(Keyword::LIKE) {
                        Ok(Expr::Like {
                            negated,
                            expr: Box::new(expr.to_owned()),
                            pattern: Box::new(some_q!(parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC))),
                            escape_char: some_q!(parser.parse_escape_char()),
                        })
                    } else if parser.parse_keyword(Keyword::ILIKE) {
                        Ok(Expr::ILike {
                            negated,
                            expr: Box::new(expr.to_owned()),
                            pattern: Box::new(some_q!(parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC))),
                            escape_char: some_q!(parser.parse_escape_char()),
                        })
                    } else if parser.parse_keywords(&[Keyword::SIMILAR, Keyword::TO]) {
                        Ok(Expr::SimilarTo {
                            negated,
                            expr: Box::new(expr.to_owned()),
                            pattern: Box::new(some_q!(parser.parse_subexpr(Self::BETWEEN_IN_LIKE_ILIKE_SIMILAR_PREC))),
                            escape_char: some_q!(parser.parse_escape_char()),
                        })
                    } else {
                        parser.expected("IN or BETWEEN after NOT", parser.peek_token())
                    }
                }
                // Can only happen if `get_next_precedence` got out of sync with this function
                _ => parser_err!(format!("No infix parser for token {:?}", tok.token)),
            }
        } else if Token::DoubleColon == tok {
            parser.parse_pg_cast(expr.to_owned())
        } else if Token::ExclamationMark == tok {
            // PostgreSQL factorial operation
            Ok(Expr::UnaryOp {
                op: UnaryOperator::PGPostfixFactorial,
                expr: Box::new(expr.to_owned()),
            })
        } else if Token::LBracket == tok {
            parser.parse_array_index(expr.to_owned())
        } else if Token::Colon == tok {
            Ok(Expr::JsonAccess {
                left: Box::new(expr.to_owned()),
                operator: JsonOperator::Colon,
                right: Box::new(Expr::Value(some_q!(parser.parse_value()))),
            })
        } else if Token::Arrow == tok
            || Token::LongArrow == tok
            || Token::HashArrow == tok
            || Token::HashLongArrow == tok
            || Token::AtArrow == tok
            || Token::ArrowAt == tok
            || Token::HashMinus == tok
            || Token::AtQuestion == tok
            || Token::AtAt == tok
        {
            let operator = match tok.token {
                Token::Arrow => JsonOperator::Arrow,
                Token::LongArrow => JsonOperator::LongArrow,
                Token::HashArrow => JsonOperator::HashArrow,
                Token::HashLongArrow => JsonOperator::HashLongArrow,
                Token::AtArrow => JsonOperator::AtArrow,
                Token::ArrowAt => JsonOperator::ArrowAt,
                Token::HashMinus => JsonOperator::HashMinus,
                Token::AtQuestion => JsonOperator::AtQuestion,
                Token::AtAt => JsonOperator::AtAt,
                _ => unreachable!(),
            };
            Ok(Expr::JsonAccess {
                left: Box::new(expr.to_owned()),
                operator,
                right: Box::new(some_q!(parser.parse_expr())),
            })
        } else {
            // Can only happen if `get_next_precedence` got out of sync with this function
            parser_err!(format!("No infix parser for token {:?}", tok.token))
        })
    }

    fn parse_statement(&self, parser: &mut Parser) -> Option<Result<Statement, ParserError>> {
        if parser.parse_keyword(Keyword::COMMENT) {
            Some(parse_comment(parser))
        } else {
            None
        }
    }

    fn supports_filter_during_aggregation(&self) -> bool {
        true
    }
}

pub fn parse_comment(parser: &mut Parser) -> Result<Statement, ParserError> {
    parser.expect_keyword(Keyword::ON)?;
    let token = parser.next_token();

    let (object_type, object_name) = match token.token {
        Token::Word(w) if w.keyword == Keyword::COLUMN => {
            let object_name = parser.parse_object_name()?;
            (CommentObject::Column, object_name)
        }
        Token::Word(w) if w.keyword == Keyword::TABLE => {
            let object_name = parser.parse_object_name()?;
            (CommentObject::Table, object_name)
        }
        _ => parser.expected("comment object_type", token)?,
    };

    parser.expect_keyword(Keyword::IS)?;
    let comment = if parser.parse_keyword(Keyword::NULL) {
        None
    } else {
        Some(parser.parse_literal_string()?)
    };
    Ok(Statement::Comment {
        object_type,
        object_name,
        comment,
    })
}
