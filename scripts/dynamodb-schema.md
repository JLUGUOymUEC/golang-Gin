# DynamoDB 表结构要求

代码依赖以下表结构与二级索引。**这些不在代码里创建**，需要在 DynamoDB 中手动建好，
否则查询会报 `ValidationException`（key schema mismatch / index not found）。

## 表与主键

| 表名 | 分区键 | 代码位置 |
|---|---|---|
| `Users` | `user_id` (S) | `dynamodb_user.go` |
| `Sessions` | `session_id` (S) | `dynamodb_session.go` |
| `AuthTokens` | `auth_token_id` (S) | `dynamodb_auth_token.go` |
| `AccessTokens` | `access_token_id` (S) | `dynamodb_access_token.go` |
| `RefreshTokens` | `refresh_token_id` (S) | `dynamodb_refresh_token.go` |
| `OAuthClients` | `client_id` (S) | `dynamodb_client.go` |

所有表都需要开启 **TTL**，属性名为 `ttl`。

## 必需的单字段 GSI

| 表 | 索引名 | 分区键 | 用途 | 代码位置 |
|---|---|---|---|---|
| `Users` | `email-index` | `email` (S) | 按邮箱登录 | `dynamodb_user.go` `GetUserByEmail` |
| `Users` | `username-index` | `username` (S) | 按用户名登录 | `dynamodb_user.go` `GetUserByUsername` |
| `Sessions` | `user_id-index` | `user_id` (S) | 列出用户会话（登出/改密码） | `dynamodb_session.go` `GetSessionIDsByUserID` |
| `AccessTokens` | `user_id-index` | `user_id` (S) | **登出时撤销全部 access token** | `dynamodb_access_token.go` `RevokeAllByUserID` |
| `RefreshTokens` | `user_id-index` | `user_id` (S) | **登出时撤销全部 refresh token** | `dynamodb_refresh_token.go` `RevokeAllByUserID` |

索引名必须完全一致（`user_id-index`，不是 `userID-index`）。

### 建索引示例（AWS CLI）

```bash
aws dynamodb update-table \
  --table-name AccessTokens \
  --attribute-definitions AttributeName=user_id,AttributeType=S \
  --global-secondary-index-updates \
    "[{\"Create\":{\"IndexName\":\"user_id-index\",\"KeySchema\":[{\"AttributeName\":\"user_id\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"}}}]"

aws dynamodb update-table \
  --table-name RefreshTokens \
  --attribute-definitions AttributeName=user_id,AttributeType=S \
  --global-secondary-index-updates \
    "[{\"Create\":{\"IndexName\":\"user_id-index\",\"KeySchema\":[{\"AttributeName\":\"user_id\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"}}}]"
```

## 一致性注意事项

GSI 是**最终一致**的。`RevokeAllByUserID` 先 Query 索引、再逐个撤销，
所以**刚刚创建、还没进入索引的 token 可能被漏掉**。

这个窗口很窄（通常毫秒级），对登出/改密码场景可以接受；如果需要更强保证，
可以在撤销后短暂重试，或改用「用户级吊销水位」方案（在 `Users` 上加
`token_valid_after` 时间戳，`ValidateAccessToken` 比对 `iat`）。

## 其他已知的表结构风险

- `dynamodb_access_token.go` / `dynamodb_auth_token.go` 的 `GetTokensByUserID`
  用 `GetItem` + `user_id` 作主键，这是**错误的**（主键是 token id）。
  目前没有任何调用点，属于遗留代码；若要使用需改成上面的 GSI Query。
- `dynamodb_user.go` 的 `UpdateUser` 把字段写成 `hashed_password`，
  与 `User` 结构体的 `dynamodbav:"hashed_password"` 一致，是对的；
  但如果库里有历史数据用的是 `password` 属性名，需要迁移。
