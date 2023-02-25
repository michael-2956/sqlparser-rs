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

use crate::ast::{CommentObject, Statement};
use crate::dialect::Dialect;
use crate::keywords::Keyword;
use crate::parser::{Parser, ParserError};
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
    //  + -	unary plus, unary minus. It is supposed that parse_prefix parses
    // this out without needing to call get_next_precedence
    // const UNARY_PLUS_MINUS_PREC: u8 = 20;
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
            Token::LBracket | Token::RBracket => Self::BRACKET_ARRAY_ELEMENT_PREC,
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
