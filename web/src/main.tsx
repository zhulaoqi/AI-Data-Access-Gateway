import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import {
  ApiOutlined,
  AuditOutlined,
  ClusterOutlined,
  DatabaseOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  ExperimentOutlined,
  ExpandAltOutlined,
  EyeOutlined,
  InboxOutlined,
  IdcardOutlined,
  LinkOutlined,
  KeyOutlined,
  LockOutlined,
  MenuOutlined,
  PlusOutlined,
  RightCircleOutlined,
  SafetyOutlined,
  ShrinkOutlined,
  StopOutlined,
  SyncOutlined,
  TeamOutlined,
  TagsOutlined
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Collapse,
  ConfigProvider,
  Descriptions,
  Dropdown,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Pagination,
  Popconfirm,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Transfer,
  Tree,
  Upload,
  Typography,
  theme
} from "antd";
import type { TransferProps, TreeDataNode } from "antd";
import type { FormInstance } from "antd/es/form";
import type { ColumnsType } from "antd/es/table";
import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";
import zhTW from "antd/locale/zh_TW";
import {
  SECRET_PLACEHOLDER_BULLETS,
  datasourceConfigFromFormValues,
  datasourceHasConfiguredPassword,
  datasourceFormValuesFromConfig,
  maskingConfigFromFormValues,
  maskingFormValuesFromConfig,
} from "./configForms";
import {
  buildDirectoryImporterConfig,
  buildDirectoryImportPayload,
  buildUserCreatePayload,
  directoryImportTemplateFields,
  parseDirectoryRowsFromFile,
} from "./directoryForms";
import { AdminOnboarding } from "./AdminOnboarding";
import { validateAdminApiKey } from "./adminAuth";
import { ApiKeyField } from "./ApiKeyField";
import { findTreePathByKey } from "./catalogNavigation";
import { CompactActionButton } from "./CompactActionButton";
import { languageOptions, resolveInitialLanguage, type Language } from "./language";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { buildMcpPlatformGuides, type McpPlatformGuide, type McpSetupPayload } from "./mcpGuides";
import "./styles.css";

type PageKey =
  | "overview"
  | "users"
  | "roles"
  | "datasources"
  | "tags"
  | "policies"
  | "masking"
  | "apiKeys"
  | "audit"
  | "mcp";

type AnyRecord = Record<string, any>;
type PageRequest = { limit: number; offset: number };
type PaginatedResponse<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};
type PaginationState = PaginatedResponse<unknown> & {
  setPage: (limit: number, offset: number) => void;
};

const DEFAULT_PAGE_LIMIT = 50;

function isPaginatedResponse<T>(payload: unknown): payload is PaginatedResponse<T> {
  return Boolean(
    payload
      && typeof payload === "object"
      && Array.isArray((payload as PaginatedResponse<T>).items)
      && typeof (payload as PaginatedResponse<T>).total === "number"
      && typeof (payload as PaginatedResponse<T>).limit === "number"
      && typeof (payload as PaginatedResponse<T>).offset === "number"
  );
}

function paginatedPath(path: string, page: PageRequest) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}limit=${page.limit}&offset=${page.offset}`;
}

async function loadAllPaginated<T>(
  request: <R>(path: string, init?: RequestInit) => Promise<R>,
  path: string,
) {
  const pageSize = 500;
  const first = await request<T[] | PaginatedResponse<T>>(paginatedPath(path, { limit: pageSize, offset: 0 }));
  if (!isPaginatedResponse<T>(first)) return first;
  const items = [...first.items];
  for (let offset = first.offset + first.limit; offset < first.total; offset += first.limit) {
    const next = await request<PaginatedResponse<T>>(paginatedPath(path, { limit: first.limit, offset }));
    if (!isPaginatedResponse<T>(next)) break;
    items.push(...next.items);
  }
  return items;
}

type DirectoryUserRecord = {
  id?: string;
  user_id?: string;
  name: string;
  external_ref: string;
  org_node_id?: string | null;
  org_path?: string | null;
  role_ids: string[];
  role_names: string[];
  status: string;
};
type OrgTreeNode = {
  key: string;
  title: string;
  path?: string;
  directUserNames?: string[];
  parentId?: string | null;
  isRoot?: boolean;
  children?: OrgTreeNode[];
};
type CatalogTreeNode = AnyRecord & {
  key: string;
  type: "datasource" | "resource" | "field";
  children?: CatalogTreeNode[];
};
type CatalogJumpTarget = {
  /** Tree node key that should be focused after navigating into the datasource workspace. */
  key: string;
};
type McpPlatformKey = McpPlatformGuide["key"];
type TranslationParams = Record<string, string | number>;
type ImportPlatformKey = "feishu" | "wecom" | "dingtalk";
type PolicyTargetMode = "resource" | "tag";

const translations = {
  "en-US": {
    "brand.productName": "AI Data Access Gateway",
    "brand.controlPlane": "Control Plane",
    "topbar.kicker": "Secure data operations",
    "topbar.apiKey": "API key",
    "topbar.showApiKey": "Show API key",
    "topbar.hideApiKey": "Hide API key",
    "topbar.language": "Language",
    "topbar.switchLanguage": "Switch page language",
    "topbar.openNavigation": "Open navigation",
    "topbar.navigation": "Navigation",
    "nav.overview": "Overview",
    "nav.users": "Users",
    "nav.roles": "Roles",
    "nav.datasources": "Data Sources",
    "nav.tags": "Tags",
    "nav.policies": "Policies",
    "nav.masking": "Masking",
    "nav.apiKeys": "API Keys",
    "nav.audit": "Audit Logs",
    "nav.mcp": "MCP Setup",
    "stats.datasources": "Data sources",
    "stats.resources": "Resources",
    "stats.audit": "Audit events",
    "common.create": "Create",
    "common.createKey": "Create key",
    "common.save": "Save",
    "common.refresh": "Refresh",
    "common.rows": "{count} rows",
    "common.view": "View",
    "common.edit": "Edit",
    "common.delete": "Delete",
    "common.saved": "Saved",
    "common.deleted": "Deleted",
    "common.revoke": "Revoke",
    "common.revoked": "Revoked",
    "common.detailsTitle": "{title} Details",
    "common.createTitle": "Create {title}",
    "common.editTitle": "Edit {title}",
    "common.deleteConfirm": "Delete {title}?",
    "common.revokeConfirm": "Revoke this key?",
    "common.required": "{label} is required",
    "common.validJson": "{label} must be valid JSON",
    "common.yes": "Yes",
    "common.no": "No",
    "common.confirm": "OK",
    "common.cancel": "Cancel",
    "placeholder.datasourceSearch": "Search and select a datasource",
    "placeholder.resourceSearch": "Search and select a resource",
    "placeholder.tagSearch": "Search and select a tag",
    "placeholder.roleSearch": "Select one or more roles",
    "placeholder.orgNodeSearch": "Select an organization node",
    "apiKey.newTitle": "New API key",
    "apiKey.serviceTitle": "Service and operator keys",
    "apiKey.serviceDescription": "Runtime user keys are managed from the Users workspace. This page only creates admin control-plane keys.",
    "apiKey.serviceCreate": "Create service key",
    "field.name": "Name",
    "field.type": "Type",
    "field.status": "Status",
    "field.config": "Config",
    "field.host": "Host",
    "field.port": "Port",
    "field.database": "Database",
    "field.username": "Username",
    "field.password": "Password",
    "field.displayName": "Display name",
    "field.queryLanguage": "Query language",
    "field.category": "Category",
    "field.description": "Description",
    "field.subjectType": "Subject type",
    "field.subject": "Subject",
    "field.effect": "Effect",
    "field.action": "Action",
    "field.allowDecrypt": "Allow decrypt",
    "field.resourceId": "Resource",
    "field.field": "Field",
    "field.tagId": "Tag ID",
    "field.priority": "Priority",
    "field.strategy": "Strategy",
    "field.externalRef": "External reference",
    "field.orgNode": "Organization node",
    "field.roles": "Roles",
    "field.orgDelimiter": "Organization path delimiter",
    "field.replacement": "Replacement",
    "field.prefix": "Visible prefix",
    "field.suffix": "Visible suffix",
    "field.fill": "Mask character",
    "field.scopes": "Scopes",
    "tab.resource": "Resource",
    "tab.field": "Field",
    "tab.tag": "Tag",
    "policy.resourcePolicies": "Resource Policies",
    "policy.fieldPolicies": "Field Policies",
    "policy.availableResources": "Available resources",
    "policy.selectedResources": "Selected resources",
    "policy.searchResources": "Search resources",
    "policy.resourceItemUnit": "item",
    "policy.resourceItemsUnit": "items",
    "policy.expandAllResources": "Expand all",
    "policy.collapseAllResources": "Collapse all",
    "section.fields": "Fields",
    "datasource.new": "New data source",
    "datasource.test": "Test",
    "datasource.scan": "Sync metadata",
    "datasource.tested": "Connection test passed",
    "datasource.scanned": "Metadata synced",
    "datasource.deleteConfirm": "Delete this data source and scanned metadata?",
    "datasource.configHint": "Use explicit connection fields instead of pasting JSON.",
    "datasource.passwordPlaceholder": "Leave blank to keep the stored password",
    "catalog.search": "Search data sources, databases, tables, or fields",
    "catalog.selectPrompt": "Select a data source, database, table, or field to edit details.",
    "catalog.treeTitle": "Data Sources",
    "catalog.detailsTitle": "Catalog Details",
    "catalog.nodeType": "Node type",
    "catalog.fieldInfo": "Field information",
    "catalog.disabledHint": "Disabled assets are hidden from runtime resource discovery.",
    "catalog.tags": "Tags",
    "catalog.noTags": "No tags assigned",
    "catalog.addTag": "Add tag",
    "catalog.jump": "Open in Data Sources",
    "users.new": "New user",
    "users.importExcel": "Import user data",
    "users.organizationTree": "Organization tree",
    "users.directory": "User directory",
    "users.details": "User details",
    "users.emptySelection": "Select a user to inspect roles, organization placement, and runtime key actions.",
    "users.emptyUsers": "No users loaded yet",
    "users.emptyUsersHint": "Create a user or run an import to populate the directory workspace.",
    "users.runtimeKey": "Runtime key",
    "users.generateKey": "Generated from user operations",
    "users.resetKey": "Reset runtime key",
    "users.latestKey": "Latest plaintext key",
    "users.importTitle": "User data import",
    "audit.viewDetails": "View audit log details",
    "audit.rawSql": "Raw query SQL",
    "audit.emptySql": "No SQL text available for this event.",
    "users.uploadFile": "Upload file",
    "users.dragFileHere": "Drag file here",
    "users.importHint": "Use the approved template columns: user_name, org_path, external_ref, roles.",
    "users.previewImport": "Preview import",
    "users.executeImport": "Execute import",
    "users.previewSummary": "Import preview",
    "users.orgNodesToCreate": "Org nodes to create",
    "users.rolesToCreate": "Roles to create",
    "users.usersCreated": "Users created",
    "users.usersUpdated": "Users updated",
    "users.keysCreated": "Runtime keys created",
    "users.rootMapped": "Users without an organization path are placed under the / root node.",
    "users.importReady": "Upload a file to preview org changes, new roles, and affected users.",
    "users.downloadTemplate": "Download template",
    "users.templateGuide": "Template fields",
    "users.templateGuideSummary": "Fill the template first, then upload the edited Excel file. Required columns must stay in place.",
    "users.field": "Field",
    "users.required": "Required",
    "users.format": "Format",
    "users.requirement": "Requirement",
    "users.templateField.user_name.format": "Plain text, one user name per row",
    "users.templateField.user_name.notes": "Required. Use the display name that admins should see in the console.",
    "users.templateField.org_path.format": "Delimited path, for example Company/Finance/BI",
    "users.templateField.org_path.notes": "Optional. Empty values place the user under the root organization node. Missing nodes are created automatically.",
    "users.templateField.external_ref.format": "Stable unique identifier, for example EMP001 or ext_user_123",
    "users.templateField.external_ref.notes": "Required. The import pipeline uses this field to decide whether to create or update a user.",
    "users.templateField.roles.format": "Comma-separated role names, for example Analyst,Reviewer",
    "users.templateField.roles.notes": "Optional. Missing roles are created automatically during import.",
    "users.importPlatform": "Platform import",
    "users.importPlatformHint": "Fill the official app credentials for one platform. The gateway will pull departments and users directly from that platform when you preview or execute the import.",
    "users.platformGuide": "Setup guide",
    "users.platformGuidePermissions": "Required permissions",
    "users.platformGuideManifest":
      "In Feishu developer console, open Permission management -> Batch import/export permissions and paste this JSON:",
    "users.platformGuideManifestNote":
      "After adding permissions, you must create and publish a new app version, then wait for enterprise admin approval before the permissions take effect.",
    "users.platformAppId": "App ID",
    "users.platformAppSecret": "App secret",
    "users.platformCorpId": "Corp ID",
    "users.platformCorpSecret": "Contact secret",
    "users.platformAppKey": "App key",
    "users.platformRootDepartmentId": "Root department ID",
    "users.platformRootDepartmentHint": "Optional. Limit the import to one branch. Leave the default root department ID when you want the full tree.",
    "users.platformFeishuStep1":
      "Open open.feishu.cn, sign in, enter the developer console, and create an internal enterprise app.",
    "users.platformFeishuStep2":
      "In the left menu, open Credentials & Basic Info, copy the App ID and App Secret, then fill them in below and save the configuration.",
    "users.platformFeishuStep3":
      "In the left menu, open Permission management, click Batch import/export permissions, paste the JSON below, and confirm the import.",
    "users.platformFeishuStep4":
      "Required: in Version management & release, create a version, set availability to all employees, submit it for release, and wait for enterprise admin approval. Unlike DingTalk, Feishu permissions do not take effect until the app version is released and approved.",
    "users.platformFeishuPermissions":
      "The app must include contact:contact.base:readonly, contact:department.base:readonly, contact:user.base:readonly, and contact:user.employee_id:readonly.",
    "users.platformWecomStep1": "Create or reuse a Contacts Secret in Enterprise WeChat and grant read-only access to departments and members.",
    "users.platformWecomStep2": "Fill in the Corp ID, Contacts Secret, and the root department ID. The default root department ID is 1 for full-tree imports.",
    "users.platformWecomStep3": "Preview the generated organization paths before running the import. The gateway resolves department ids into full paths automatically.",
    "users.platformWecomPermissions": "Contacts read permission and a Contacts Secret that can call department and member directory APIs.",
    "users.platformDingtalkStep1": "Configure an internal app in DingTalk and grant read-only department and member permissions.",
    "users.platformDingtalkStep2": "Fill in the App Key, App Secret, and the root department ID. The default root department ID is 1 for full-tree imports.",
    "users.platformDingtalkStep3": "Preview first. The gateway builds full department paths from DingTalk departments before creating or updating users.",
    "users.platformDingtalkPermissions": "Department read and member read permissions for the internal app.",
    "users.orgCreateRoot": "Create node",
    "users.orgCreateSibling": "Create sibling node",
    "users.orgCreateChild": "Add child node",
    "users.orgEdit": "Edit node",
    "users.orgDelete": "Delete node",
    "users.orgDeleteConfirm": "Delete this organization node?",
    "users.orgRootDeleteDisabled": "The / root node cannot be deleted.",
    "users.orgNodeTitle": "Organization node",
    "users.orgNodeMembers": "Direct members",
    "users.orgNodeSelected": "Selected node",
    "users.importTabExcel": "Excel",
    "users.importTabFeishu": "Feishu",
    "users.importTabWecom": "WeCom",
    "users.importTabDingtalk": "DingTalk",
    "roles.directory": "Role directory",
    "roles.summary": "Independent directory roles used by runtime authorization.",
    "roles.activeCount": "Active roles",
    "roles.emptyDescription": "No description provided.",
    "roles.new": "Create",
    "roles.userCount": "Linked users",
    "roles.linkedUsers": "View linked users",
    "roles.linkedUsersTitle": "{name} linked users",
    "masking.fixedHint": "Fixed masking always returns the same replacement text.",
    "masking.partialHint": "Partial masking keeps the start and end of the value visible.",
    "masking.noConfig": "This masking strategy does not require extra configuration.",
    "tag.relatedAssets": "Linked assets",
    "tag.relatedAssetsTitle": "{name} linked assets",
    "tag.noLinkedAssets": "No data assets are currently linked to this tag.",
    "onboarding.title": "Admin Login",
    "onboarding.description":
      "Enter an admin API key to unlock the control plane. If you have not created one yet, expand the initialization guide below and choose the path that matches your deployment style.",
    "onboarding.inputLabel": "Admin API key",
    "onboarding.inputPlaceholder": "Paste the key printed by init-admin",
    "onboarding.continue": "Sign In",
    "onboarding.methodsTitle": "How to initialize an admin API key",
    "onboarding.method.python": "Native Python",
    "onboarding.method.pythonDescription": "Use this when the project is installed into a regular Python environment without uv wrappers.",
    "onboarding.method.uv": "uv",
    "onboarding.method.uvDescription": "Use this when you manage the project with uv and want the shortest local bootstrap path.",
    "onboarding.method.docker": "Docker",
    "onboarding.method.dockerDescription": "Use this when the backend is already running inside Docker Compose and you want to initialize the key from the container.",
    "onboarding.authErrorTitle": "Authentication failed",
    "mcp.summaryTitle": "Remote MCP endpoint",
    "mcp.summaryDescription": "Connect external MCP clients with each user's unique runtime-scoped API key. ADG derives runtime identity from the user bound to that key.",
    "mcp.serverUrl": "MCP server URL",
    "mcp.toolUrl": "Supplemental HTTP tool API",
    "mcp.transport": "Transport",
    "mcp.transportValue": "Streamable HTTP",
    "mcp.authMode": "Authentication",
    "mcp.authModeValue": "Send a runtime-scoped API key in the {header} header on every MCP request.",
    "mcp.apiKeyHeader": "API key header",
    "mcp.tools": "Tool catalog",
    "mcp.platformsTitle": "Client setup guides",
    "mcp.platformsDescription": "Pick your agent client and copy the matching config snippet and setup steps.",
    "mcp.notesTitle": "Connection notes",
    "mcp.note.runtimeKey": "Each user should use their own runtime-scoped API key here. Admin-only keys cannot call runtime MCP tools.",
    "mcp.note.identity": "Runtime identity, organization placement, and roles are derived automatically from the user bound to the API key.",
    "mcp.note.reload": "Restart the client, or reload its MCP configuration, after editing local config files.",
    "mcp.platform.codex.title": "Codex App",
    "mcp.platform.codex.summary": "Register the remote MCP server in ~/.codex/config.toml and attach the signed-in user's runtime API key as HTTP headers.",
    "mcp.platform.codex.step1": "Open ~/.codex/config.toml on the machine that runs Codex.",
    "mcp.platform.codex.step2": "Paste the TOML block below and point the environment variable at the current user's unique runtime API key.",
    "mcp.platform.codex.step3": "Save the file, then restart Codex or reload MCP servers.",
    "mcp.platform.claude-code.title": "Claude Code",
    "mcp.platform.claude-code.summary": "Claude Code can add remote MCP servers from JSON and also understands project-level .mcp.json files.",
    "mcp.platform.claude-code.step1": "Use the CLI snippet for a quick import, or paste the JSON snippet into your project's .mcp.json file.",
    "mcp.platform.claude-code.step2": "Store the current user's unique runtime API key in an environment variable before launching Claude Code.",
    "mcp.platform.claude-code.step3": "Run /mcp inside Claude Code to verify the server and manage authentication state.",
    "mcp.platform.trae.title": "Trae",
    "mcp.platform.trae.summary": "Trae can import MCP servers from the settings panel or from a workspace-level .trae/mcp.json file.",
    "mcp.platform.trae.step1": "Open Settings > MCP, choose manual configuration, and select Streamable HTTP when prompted.",
    "mcp.platform.trae.step2": "Paste the JSON snippet below, or save the same content into .trae/mcp.json in your project root.",
    "mcp.platform.trae.step3": "Reload the MCP panel or restart Trae so the new server and tools appear.",
    "mcp.platform.mcporter.title": "mcporter",
    "mcp.platform.mcporter.summary": "mcporter can consume remote MCP servers from its own JSONC config and reuse the same server from scripts or the CLI.",
    "mcp.platform.mcporter.step1": "Create config/mcporter.json in your project, or use ~/.mcporter/mcporter.json for a user-level setup.",
    "mcp.platform.mcporter.step2": "Paste the JSON snippet below and store the current user's unique runtime API key in ADG_USER_RUNTIME_KEY.",
    "mcp.platform.mcporter.step3": "Run mcporter list adg to confirm the server and inspect the imported tool signatures.",
    "mcp.tool.list_datasources": "List the datasources visible to the current runtime identity.",
    "mcp.tool.list_tags": "List the governance tags visible to the current runtime identity.",
    "mcp.tool.list_resources": "List readable tables under one datasource. description is the business meaning of the table when one was written, otherwise the database comment. database_description is the business meaning of the database.",
    "mcp.tool.list_resources_by_tag": "Find readable resources by one or more governance tag names.",
    "mcp.tool.describe_resource": "Describe one table and its readable columns. description and database_description are business meanings. Each column description is the business meaning of that field when one was written, otherwise the database comment.",
    "mcp.tool.preview_resource": "Preview rows from one resource with policy and masking enforcement.",
    "mcp.tool.execute_query": "Run one read-only SQL query scoped to declared resources.",
    "option.active": "active",
    "option.disabled": "disabled",
    "option.all": "all users",
    "option.allow": "allow",
    "option.deny": "deny",
    "option.allowed": "allowed",
    "option.denied": "denied",
    "option.user": "user",
    "option.role": "role",
    "option.fixed": "fixed",
    "option.partial": "partial",
    "option.hash": "hash",
    "option.reversible": "reversible",
    "option.postgres": "postgres",
    "option.mysql": "mysql",
    "option.doris": "doris",
    "option.database": "database",
    "option.schema": "schema",
    "option.relational_table": "table",
    "option.relational_view": "view",
    "column.id": "ID",
    "column.datasource_id": "Datasource",
    "column.datasource_label": "Datasource",
    "column.datasource_count": "Datasource count",
    "column.resource_id": "Resource",
    "column.resource_label": "Resource",
    "column.resource_count": "Resource count",
    "column.api_key_id": "API key",
    "column.user_id": "User ID",
    "column.user_name": "User",
    "column.user_org_path": "Organization",
    "column.name": "Name",
    "column.type": "Type",
    "column.datasource_kind": "Datasource kind",
    "column.config": "Config",
    "column.status": "Status",
    "column.created_at": "Created at",
    "column.updated_at": "Updated at",
    "column.kind": "Kind",
    "column.path": "Path",
    "column.display_name": "Display name",
    "column.query_language": "Query language",
    "column.scanned_at": "Scanned at",
    "column.category": "Category",
    "column.description": "Description",
    "column.subject_type": "Subject type",
    "column.subject_id": "Subject",
    "column.subject_label": "Subject",
    "column.effect": "Effect",
    "column.action": "Action",
    "column.tag_id": "Tag ID",
    "column.tag_name": "Tag name",
    "column.tag_count": "Tag count",
    "column.priority": "Priority",
    "column.field_name": "Field",
    "column.allow_decrypt": "Allow decrypt",
    "column.strategy": "Strategy",
    "column.subject": "Subject",
    "column.scopes": "Scopes",
    "column.expires_at": "Expires at",
    "column.event_type": "Event type",
    "column.decision": "Decision",
    "column.reason": "Reason",
    "column.resource_ids": "Resources",
    "column.query_id": "Query ID",
    "column.data_type": "Data type",
    "column.nullable": "Nullable",
    "column.ordinal_position": "Position",
    "column.metadata": "Metadata",
    "column.external_ref": "External reference",
    "column.org_path": "Organization path",
    "column.role_names": "Roles",
    "column.actions": "Actions",
    "option.metadata_discovery": "Metadata discovery",
    "option.resource_preview": "Resource preview",
    "option.query_execution": "Query execution",
    "option.permission_rejected": "Permission rejected",
    "option.audit_sql_view": "Audit SQL viewed",
    "option.decryption": "Decryption",
    "option.query_allowed": "Query allowed"
  },
  "zh-CN": {
    "brand.productName": "AI 数据库连接网关",
    "brand.controlPlane": "控制平面",
    "topbar.kicker": "安全数据操作",
    "topbar.apiKey": "API 密钥",
    "topbar.showApiKey": "显示 API 密钥",
    "topbar.hideApiKey": "隐藏 API 密钥",
    "topbar.language": "语言",
    "topbar.switchLanguage": "切换页面语言",
    "topbar.openNavigation": "打开导航",
    "topbar.navigation": "导航",
    "nav.overview": "概览",
    "nav.users": "用户",
    "nav.roles": "角色",
    "nav.datasources": "数据源",
    "nav.tags": "标签",
    "nav.policies": "权限策略",
    "nav.masking": "脱敏",
    "nav.apiKeys": "API 密钥",
    "nav.audit": "审计日志",
    "nav.mcp": "MCP 设置",
    "stats.datasources": "数据源",
    "stats.resources": "资源",
    "stats.audit": "审计事件",
    "common.create": "新建",
    "common.createKey": "新建密钥",
    "common.save": "保存",
    "common.refresh": "刷新",
    "common.rows": "{count} 行",
    "common.view": "查看",
    "common.edit": "编辑",
    "common.delete": "删除",
    "common.saved": "已保存",
    "common.deleted": "已删除",
    "common.revoke": "撤销",
    "common.revoked": "已撤销",
    "common.detailsTitle": "{title}详情",
    "common.createTitle": "新建{title}",
    "common.editTitle": "编辑{title}",
    "common.deleteConfirm": "确认删除{title}？",
    "common.revokeConfirm": "确认撤销该密钥？",
    "common.required": "请输入{label}",
    "common.validJson": "{label}必须是有效 JSON",
    "common.yes": "是",
    "common.no": "否",
    "common.confirm": "确定",
    "common.cancel": "取消",
    "placeholder.datasourceSearch": "搜索并选择数据源",
    "placeholder.resourceSearch": "搜索并选择资源",
    "placeholder.tagSearch": "搜索并选择标签",
    "placeholder.roleSearch": "选择一个或多个角色",
    "placeholder.orgNodeSearch": "选择组织节点",
    "apiKey.newTitle": "新 API 密钥",
    "apiKey.serviceTitle": "服务与操作员密钥",
    "apiKey.serviceDescription": "运行时用户密钥统一在用户工作区里生成和重置。这个页面只用于创建 admin 管理密钥。",
    "apiKey.serviceCreate": "新建服务密钥",
    "field.name": "名称",
    "field.type": "类型",
    "field.status": "状态",
    "field.config": "配置",
    "field.host": "主机",
    "field.port": "端口",
    "field.database": "数据库",
    "field.username": "用户名",
    "field.password": "密码",
    "field.displayName": "显示名称",
    "field.queryLanguage": "查询语言",
    "field.category": "分类",
    "field.description": "描述",
    "field.subjectType": "主体类型",
    "field.subject": "主体",
    "field.effect": "效果",
    "field.action": "操作",
    "field.allowDecrypt": "允许解密",
    "field.resourceId": "资源",
    "field.field": "字段",
    "field.tagId": "标签 ID",
    "field.priority": "优先级",
    "field.strategy": "策略",
    "field.externalRef": "外部标识",
    "field.orgNode": "组织节点",
    "field.roles": "角色",
    "field.orgDelimiter": "组织架构分隔符",
    "field.replacement": "替换文本",
    "field.prefix": "保留前缀",
    "field.suffix": "保留后缀",
    "field.fill": "掩码字符",
    "field.scopes": "权限范围",
    "tab.resource": "资源",
    "tab.field": "字段",
    "tab.tag": "标签",
    "policy.resourcePolicies": "资源权限策略",
    "policy.fieldPolicies": "字段权限策略",
    "policy.availableResources": "可选资源",
    "policy.selectedResources": "已选资源",
    "policy.searchResources": "搜索资源",
    "policy.resourceItemUnit": "项",
    "policy.resourceItemsUnit": "项",
    "policy.expandAllResources": "全部展开",
    "policy.collapseAllResources": "全部折叠",
    "section.fields": "字段",
    "datasource.new": "新建数据源",
    "datasource.test": "测试连接",
    "datasource.scan": "同步元数据",
    "datasource.tested": "连接测试通过",
    "datasource.scanned": "元数据已同步",
    "datasource.deleteConfirm": "确认删除该数据源及其扫描元数据？",
    "datasource.configHint": "使用明确的连接字段填写配置，不需要手写 JSON。",
    "datasource.passwordPlaceholder": "留空即可保留当前已保存的密码",
    "catalog.search": "搜索数据源、库、表或字段",
    "catalog.selectPrompt": "选择一个数据源、数据库、数据表或字段来维护详情。",
    "catalog.treeTitle": "数据源",
    "catalog.detailsTitle": "目录详情",
    "catalog.nodeType": "节点类型",
    "catalog.fieldInfo": "字段信息",
    "catalog.disabledHint": "停用的资产不会出现在运行时资源发现结果中。",
    "catalog.tags": "标签",
    "catalog.noTags": "暂未绑定标签",
    "catalog.addTag": "添加标签",
    "catalog.jump": "打开数据源页",
    "users.new": "新建用户",
    "users.importExcel": "用户数据导入",
    "users.organizationTree": "组织树",
    "users.directory": "用户目录",
    "users.details": "用户详情",
    "users.emptySelection": "选择一个用户，查看其角色、组织归属和运行时密钥操作。",
    "users.emptyUsers": "暂无用户数据",
    "users.emptyUsersHint": "新建用户或执行导入后，这里会出现目录用户列表。",
    "users.runtimeKey": "运行时密钥",
    "users.generateKey": "仅通过用户操作生成",
    "users.resetKey": "重置运行时密钥",
    "users.latestKey": "最近一次明文密钥",
    "users.importTitle": "用户数据导入",
    "audit.viewDetails": "查看审计日志详情",
    "audit.rawSql": "原始查询 SQL",
    "audit.emptySql": "该事件没有可查看的 SQL 文本。",
    "users.uploadFile": "上传文件",
    "users.dragFileHere": "拖拽文件到这里",
    "users.importHint": "使用统一模板列：user_name、org_path、external_ref、roles。",
    "users.previewImport": "预览导入",
    "users.executeImport": "执行导入",
    "users.previewSummary": "导入预览",
    "users.orgNodesToCreate": "待创建组织节点",
    "users.rolesToCreate": "待创建角色",
    "users.usersCreated": "新建用户数",
    "users.usersUpdated": "更新用户数",
    "users.keysCreated": "新建运行时密钥数",
    "users.rootMapped": "组织路径为空的用户会挂载到 / 根节点下。",
    "users.importReady": "上传文件后先预览，再确认组织变更、角色新增和影响用户。",
    "users.downloadTemplate": "下载模板",
    "users.templateGuide": "字段说明",
    "users.templateGuideSummary": "请先下载模板并填写，再上传修改后的 Excel 文件。必填列不可删除或改名。",
    "users.field": "字段",
    "users.required": "是否必填",
    "users.format": "格式",
    "users.requirement": "要求说明",
    "users.templateField.user_name.format": "纯文本，每行一个用户姓名",
    "users.templateField.user_name.notes": "必填。这里填写管理员在控制台里应当看到的姓名。",
    "users.templateField.org_path.format": "分层路径，例如 Company/Finance/BI",
    "users.templateField.org_path.notes": "选填。留空时会放到根组织节点；缺失的层级会自动创建。",
    "users.templateField.external_ref.format": "稳定唯一标识，例如 EMP001 或 ext_user_123",
    "users.templateField.external_ref.notes": "必填。导入时会用它判断是新建用户还是更新已有用户。",
    "users.templateField.roles.format": "逗号分隔的角色名，例如 Analyst,Reviewer",
    "users.templateField.roles.notes": "选填。不存在的角色会在导入时自动创建。",
    "users.importPlatform": "平台导入",
    "users.importPlatformHint": "按平台填写官方应用凭据。预览或执行导入时，网关会直接调用对应平台的组织与用户接口，不再要求你手工粘贴返回体。",
    "users.platformGuide": "配置说明",
    "users.platformGuidePermissions": "所需权限",
    "users.platformGuideManifest": "在飞书开发者后台，进入「权限管理」->「批量导入/导出权限」，粘贴以下 JSON：",
    "users.platformGuideManifestNote":
      "注意：添加权限后，必须创建并发布应用新版本，并在企业后台审批通过后，权限才会生效。",
    "users.platformAppId": "App ID",
    "users.platformAppSecret": "App Secret",
    "users.platformCorpId": "Corp ID",
    "users.platformCorpSecret": "通讯录 Secret",
    "users.platformAppKey": "App Key",
    "users.platformRootDepartmentId": "根部门 ID",
    "users.platformRootDepartmentHint": "可选。用于把导入范围限制在某个组织分支内；如果要导入整棵组织树，就保留默认根部门 ID。",
    "users.platformFeishuStep1":
      "打开 open.feishu.cn，登录后进入开发者后台，创建企业自建应用。",
    "users.platformFeishuStep2":
      "左侧菜单进入「凭证与基础信息」，复制 App ID 和 App Secret，填入下方并保存配置。",
    "users.platformFeishuStep3":
      "左侧菜单进入「权限管理」，点击「批量导入/导出权限」，粘贴下方权限 JSON，并确认导入。",
    "users.platformFeishuStep4":
      "必须执行：左侧菜单进入「版本管理与发布」，创建版本（可用范围设为所有员工），提交审核发布，并在飞书管理后台审批通过。注意：与钉钉不同，飞书所有权限必须经过发版并由企业管理员审批后才能生效，未发布则同步无法正常使用。",
    "users.platformFeishuPermissions":
      "必须开通 contact:contact.base:readonly、contact:department.base:readonly、contact:user.base:readonly、contact:user.employee_id:readonly。",
    "users.platformWecomStep1": "在企业微信里准备可读通讯录的应用 Secret，并确认该应用具备读取部门和成员的只读权限。",
    "users.platformWecomStep2": "填写 Corp ID、通讯录 Secret 和根部门 ID。若要导入整棵树，根部门 ID 默认填 1。",
    "users.platformWecomStep3": "先预览导入结果。网关会自动把部门 ID 解析成完整组织路径。",
    "users.platformWecomPermissions": "需要通讯录只读权限，以及可调用部门和成员接口的通讯录 Secret。",
    "users.platformDingtalkStep1": "在钉钉创建企业内部应用，并授予部门与成员只读权限。",
    "users.platformDingtalkStep2": "填写 App Key、App Secret 和根部门 ID。若要导入整棵树，根部门 ID 默认填 1。",
    "users.platformDingtalkStep3": "先预览。网关会先拉取部门结构，再构建完整部门路径并创建或更新用户。",
    "users.platformDingtalkPermissions": "应用需要具备部门只读和成员只读权限。",
    "users.orgCreateRoot": "新建节点",
    "users.orgCreateSibling": "新增同级节点",
    "users.orgCreateChild": "新增子节点",
    "users.orgEdit": "编辑节点",
    "users.orgDelete": "删除节点",
    "users.orgDeleteConfirm": "确认删除该组织节点？",
    "users.orgRootDeleteDisabled": "/ 根节点不能删除。",
    "users.orgNodeTitle": "组织节点",
    "users.orgNodeMembers": "直属成员",
    "users.orgNodeSelected": "当前选中节点",
    "users.importTabExcel": "Excel",
    "users.importTabFeishu": "飞书",
    "users.importTabWecom": "企业微信",
    "users.importTabDingtalk": "钉钉",
    "roles.directory": "角色目录",
    "roles.summary": "运行时授权使用的独立目录角色。",
    "roles.activeCount": "启用角色数",
    "roles.emptyDescription": "暂无描述。",
    "roles.new": "新建",
    "roles.userCount": "关联用户数",
    "roles.linkedUsers": "查看关联用户",
    "roles.linkedUsersTitle": "{name} 的关联用户",
    "masking.fixedHint": "固定脱敏会始终返回同一段替换文本。",
    "masking.partialHint": "局部脱敏会保留值的开头和结尾可见部分。",
    "masking.noConfig": "当前脱敏策略不需要额外配置。",
    "tag.relatedAssets": "关联资源",
    "tag.relatedAssetsTitle": "{name} 的关联资源",
    "tag.noLinkedAssets": "当前没有数据资产关联到这个标签。",
    "onboarding.title": "管理员登录",
    "onboarding.description": "请输入管理员 API Key 进入控制台。如果你还没有初始化管理员密钥，可以展开下方的初始化说明，并按自己的部署方式选择命令。",
    "onboarding.inputLabel": "管理员 API Key",
    "onboarding.inputPlaceholder": "输入 init-admin 输出的密钥",
    "onboarding.continue": "登录控制台",
    "onboarding.methodsTitle": "初始化管理员 API Key",
    "onboarding.method.python": "原生 Python",
    "onboarding.method.pythonDescription": "适合已经在原生 Python 环境中安装项目的部署方式。",
    "onboarding.method.uv": "uv",
    "onboarding.method.uvDescription": "适合通过 uv 管理依赖、命令和本地开发流程的部署方式。",
    "onboarding.method.docker": "Docker",
    "onboarding.method.dockerDescription": "适合已经通过 Docker Compose 启动后端容器的部署方式。",
    "onboarding.authErrorTitle": "认证失败",
    "mcp.summaryTitle": "远程 MCP 接入地址",
    "mcp.summaryDescription": "外部 MCP 客户端应当为每个用户使用各自唯一的 runtime API Key。ADG 会根据该密钥绑定的用户自动派生运行时身份。",
    "mcp.serverUrl": "MCP 服务地址",
    "mcp.toolUrl": "补充普通 HTTP 工具地址",
    "mcp.transport": "传输方式",
    "mcp.transportValue": "Streamable HTTP",
    "mcp.authMode": "鉴权方式",
    "mcp.authModeValue": "在每一个 MCP 请求上通过 {header} 请求头传入 runtime scope 的 API Key。",
    "mcp.apiKeyHeader": "API 密钥请求头",
    "mcp.tools": "工具清单",
    "mcp.platformsTitle": "客户端接入示例",
    "mcp.platformsDescription": "按你正在使用的 AI Agent 平台选择配置方式，直接复制对应示例即可。",
    "mcp.notesTitle": "接入说明",
    "mcp.note.runtimeKey": "这里必须使用用户自己的 runtime scope API Key；只有 admin scope 的密钥不能调用运行时 MCP 工具。",
    "mcp.note.identity": "运行时身份、组织归属和角色会根据该 API Key 绑定的用户自动派生。",
    "mcp.note.reload": "修改本地配置文件之后，请重启客户端，或者重新加载 MCP 配置。",
    "mcp.platform.codex.title": "Codex App",
    "mcp.platform.codex.summary": "在 ~/.codex/config.toml 里注册远程 MCP 服务，并通过 HTTP Header 传入当前登录用户自己的 runtime API Key。",
    "mcp.platform.codex.step1": "在运行 Codex 的机器上打开 ~/.codex/config.toml。",
    "mcp.platform.codex.step2": "粘贴下方 TOML 配置，并把环境变量指向当前用户唯一的 runtime API Key 来源。",
    "mcp.platform.codex.step3": "保存文件后，重启 Codex 或重新加载 MCP servers。",
    "mcp.platform.claude-code.title": "Claude Code",
    "mcp.platform.claude-code.summary": "Claude Code 既支持通过 JSON 直接导入远程 MCP，也支持项目级 .mcp.json 配置文件。",
    "mcp.platform.claude-code.step1": "想快速导入就直接执行 CLI 示例；想做项目共享就把 JSON 示例写入项目根目录的 .mcp.json。",
    "mcp.platform.claude-code.step2": "启动 Claude Code 之前，先把当前用户唯一的 runtime API Key 放进环境变量。",
    "mcp.platform.claude-code.step3": "进入 Claude Code 后执行 /mcp，确认服务在线并检查鉴权状态。",
    "mcp.platform.trae.title": "Trae",
    "mcp.platform.trae.summary": "Trae 可以在设置面板里手动添加 MCP，也可以从工作区级别的 .trae/mcp.json 自动导入。",
    "mcp.platform.trae.step1": "打开 Settings > MCP，选择手动配置，并在界面里选用 Streamable HTTP。",
    "mcp.platform.trae.step2": "把下面的 JSON 配置粘进去，或者把同样内容保存到项目根目录的 .trae/mcp.json。",
    "mcp.platform.trae.step3": "重新打开 MCP 面板，或者重启 Trae，让新服务和工具列表生效。",
    "mcp.platform.mcporter.title": "mcporter",
    "mcp.platform.mcporter.summary": "mcporter 可以从自己的 JSONC 配置里加载远程 MCP 服务，后续在 CLI 和脚本里复用同一套服务定义。",
    "mcp.platform.mcporter.step1": "在项目里创建 config/mcporter.json；如果想做全局复用，也可以使用 ~/.mcporter/mcporter.json。",
    "mcp.platform.mcporter.step2": "粘贴下方 JSON 配置，并把当前用户唯一的 runtime API Key 存到 ADG_USER_RUNTIME_KEY 环境变量里。",
    "mcp.platform.mcporter.step3": "执行 mcporter list adg，确认服务已连通并查看自动导入的工具签名。",
    "mcp.tool.list_datasources": "列出当前运行时身份可见的数据源。",
    "mcp.tool.list_tags": "列出当前运行时身份可见的治理标签。",
    "mcp.tool.list_resources": "列出某个数据源下当前身份可读的资源。",
    "mcp.tool.list_resources_by_tag": "按一个或多个标签名称查找当前身份可读的资源。",
    "mcp.tool.describe_resource": "查看单个资源及其当前可见字段的详细信息。",
    "mcp.tool.preview_resource": "在策略和脱敏生效后预览单个资源的数据行。",
    "mcp.tool.execute_query": "在声明资源范围内执行只读 SQL 查询。",
    "option.active": "启用",
    "option.disabled": "停用",
    "option.all": "全员",
    "option.allow": "允许",
    "option.deny": "拒绝",
    "option.allowed": "允许",
    "option.denied": "拒绝",
    "option.user": "用户",
    "option.role": "角色",
    "option.fixed": "固定替换",
    "option.partial": "部分遮罩",
    "option.hash": "哈希",
    "option.reversible": "可逆加密",
    "option.postgres": "Postgres",
    "option.mysql": "MySQL",
    "option.doris": "Doris",
    "option.database": "数据库",
    "option.schema": "Schema",
    "option.relational_table": "数据表",
    "option.relational_view": "视图",
    "column.id": "ID",
    "column.datasource_id": "数据源",
    "column.datasource_label": "数据源",
    "column.datasource_count": "数据源数量",
    "column.resource_id": "资源",
    "column.resource_label": "资源",
    "column.resource_count": "资源数量",
    "column.api_key_id": "API 密钥",
    "column.user_id": "用户 ID",
    "column.user_name": "用户",
    "column.user_org_path": "所属组织",
    "column.name": "名称",
    "column.type": "类型",
    "column.datasource_kind": "数据源类型",
    "column.config": "配置",
    "column.status": "状态",
    "column.created_at": "创建时间",
    "column.updated_at": "更新时间",
    "column.kind": "类型",
    "column.path": "路径",
    "column.display_name": "显示名称",
    "column.query_language": "查询语言",
    "column.scanned_at": "扫描时间",
    "column.category": "分类",
    "column.description": "描述",
    "column.subject_type": "主体类型",
    "column.subject_id": "主体",
    "column.subject_label": "主体",
    "column.effect": "效果",
    "column.action": "操作",
    "column.tag_id": "标签 ID",
    "column.tag_name": "标签名称",
    "column.tag_count": "标签数量",
    "column.priority": "优先级",
    "column.field_name": "字段",
    "column.allow_decrypt": "允许解密",
    "column.strategy": "策略",
    "column.subject": "主体",
    "column.scopes": "权限范围",
    "column.expires_at": "过期时间",
    "column.event_type": "事件类型",
    "column.decision": "决策",
    "column.reason": "原因",
    "column.resource_ids": "资源",
    "column.query_id": "查询 ID",
    "column.data_type": "数据类型",
    "column.nullable": "可为空",
    "column.ordinal_position": "位置",
    "column.metadata": "元数据",
    "column.external_ref": "外部标识",
    "column.org_path": "组织路径",
    "column.role_names": "角色",
    "column.actions": "操作",
    "option.metadata_discovery": "元数据发现",
    "option.resource_preview": "资源预览",
    "option.query_execution": "查询执行",
    "option.permission_rejected": "权限拒绝",
    "option.audit_sql_view": "查看审计 SQL",
    "option.decryption": "数据解密",
    "option.query_allowed": "查询放行"
  },
  "zh-TW": {
    "brand.productName": "AI 資料庫連接閘道",
    "brand.controlPlane": "控制平面",
    "topbar.kicker": "安全資料操作",
    "topbar.apiKey": "API 金鑰",
    "topbar.showApiKey": "顯示 API 金鑰",
    "topbar.hideApiKey": "隱藏 API 金鑰",
    "topbar.language": "語言",
    "topbar.switchLanguage": "切換頁面語言",
    "topbar.openNavigation": "打開導覽",
    "topbar.navigation": "導覽",
    "nav.overview": "總覽",
    "nav.users": "使用者",
    "nav.roles": "角色",
    "nav.datasources": "資料來源",
    "nav.tags": "標籤",
    "nav.policies": "權限策略",
    "nav.masking": "遮罩",
    "nav.apiKeys": "API 金鑰",
    "nav.audit": "稽核日誌",
    "nav.mcp": "MCP 設定",
    "stats.datasources": "資料來源",
    "stats.resources": "資源",
    "stats.audit": "稽核事件",
    "common.create": "新增",
    "common.createKey": "新增金鑰",
    "common.save": "儲存",
    "common.refresh": "重新整理",
    "common.rows": "{count} 筆",
    "common.view": "查看",
    "common.edit": "編輯",
    "common.delete": "刪除",
    "common.saved": "已儲存",
    "common.deleted": "已刪除",
    "common.revoke": "撤銷",
    "common.revoked": "已撤銷",
    "common.detailsTitle": "{title}詳情",
    "common.createTitle": "新增{title}",
    "common.editTitle": "編輯{title}",
    "common.deleteConfirm": "確認刪除{title}？",
    "common.revokeConfirm": "確認撤銷此金鑰？",
    "common.required": "請輸入{label}",
    "common.validJson": "{label}必須是有效 JSON",
    "common.yes": "是",
    "common.no": "否",
    "common.confirm": "確定",
    "common.cancel": "取消",
    "placeholder.datasourceSearch": "搜尋並選擇資料來源",
    "placeholder.resourceSearch": "搜尋並選擇資源",
    "placeholder.tagSearch": "搜尋並選擇標籤",
    "placeholder.roleSearch": "選擇一個或多個角色",
    "placeholder.orgNodeSearch": "選擇組織節點",
    "apiKey.newTitle": "新 API 金鑰",
    "apiKey.serviceTitle": "服務與操作員金鑰",
    "apiKey.serviceDescription": "執行時使用者金鑰統一在 Users 工作區裡產生與重置。這個頁面只用於建立 admin 管理金鑰。",
    "apiKey.serviceCreate": "建立服務金鑰",
    "field.name": "名稱",
    "field.type": "類型",
    "field.status": "狀態",
    "field.config": "設定",
    "field.host": "主機",
    "field.port": "連接埠",
    "field.database": "資料庫",
    "field.username": "使用者名稱",
    "field.password": "密碼",
    "field.displayName": "顯示名稱",
    "field.queryLanguage": "查詢語言",
    "field.category": "分類",
    "field.description": "描述",
    "field.subjectType": "主體類型",
    "field.subject": "主體",
    "field.effect": "效果",
    "field.action": "操作",
    "field.allowDecrypt": "允許解密",
    "field.resourceId": "資源",
    "field.field": "欄位",
    "field.tagId": "標籤 ID",
    "field.priority": "優先順序",
    "field.strategy": "策略",
    "field.externalRef": "外部識別",
    "field.orgNode": "組織節點",
    "field.roles": "角色",
    "field.orgDelimiter": "組織架構分隔符",
    "field.replacement": "替換文字",
    "field.prefix": "保留前綴",
    "field.suffix": "保留後綴",
    "field.fill": "遮罩字元",
    "field.scopes": "權限範圍",
    "tab.resource": "資源",
    "tab.field": "欄位",
    "tab.tag": "標籤",
    "policy.resourcePolicies": "資源權限策略",
    "policy.fieldPolicies": "欄位權限策略",
    "policy.availableResources": "可選資源",
    "policy.selectedResources": "已選資源",
    "policy.searchResources": "搜尋資源",
    "policy.resourceItemUnit": "項",
    "policy.resourceItemsUnit": "項",
    "policy.expandAllResources": "全部展開",
    "policy.collapseAllResources": "全部摺疊",
    "section.fields": "欄位",
    "datasource.new": "新增資料來源",
    "datasource.test": "測試連線",
    "datasource.scan": "同步中繼資料",
    "datasource.tested": "連線測試通過",
    "datasource.scanned": "中繼資料已同步",
    "datasource.deleteConfirm": "確認刪除此資料來源及其掃描中繼資料？",
    "datasource.configHint": "使用明確的連線欄位填寫設定，不需要手寫 JSON。",
    "datasource.passwordPlaceholder": "留空即可保留目前已儲存的密碼",
    "catalog.search": "搜尋資料來源、資料庫、資料表或欄位",
    "catalog.selectPrompt": "選擇一個資料來源、資料庫、資料表或欄位來維護詳情。",
    "catalog.treeTitle": "資料來源",
    "catalog.detailsTitle": "目錄詳情",
    "catalog.nodeType": "節點類型",
    "catalog.fieldInfo": "欄位資訊",
    "catalog.disabledHint": "停用的資產不會出現在執行時資源探索結果中。",
    "catalog.tags": "標籤",
    "catalog.noTags": "尚未綁定標籤",
    "catalog.addTag": "新增標籤",
    "catalog.jump": "打開資料源頁",
    "users.new": "新增使用者",
    "users.importExcel": "使用者資料匯入",
    "users.organizationTree": "組織樹",
    "users.directory": "使用者目錄",
    "users.details": "使用者詳情",
    "users.emptySelection": "選擇一位使用者，查看其角色、組織歸屬與執行時金鑰操作。",
    "users.emptyUsers": "目前沒有使用者資料",
    "users.emptyUsersHint": "建立使用者或執行匯入後，這裡會出現目錄使用者清單。",
    "users.runtimeKey": "執行時金鑰",
    "users.generateKey": "僅透過使用者操作產生",
    "users.resetKey": "重置執行時金鑰",
    "users.latestKey": "最近一次明文金鑰",
    "users.importTitle": "使用者資料匯入",
    "audit.viewDetails": "查看稽核日誌詳情",
    "audit.rawSql": "原始查詢 SQL",
    "audit.emptySql": "此事件沒有可檢視的 SQL 文字。",
    "users.uploadFile": "上傳檔案",
    "users.dragFileHere": "將檔案拖曳到這裡",
    "users.importHint": "使用統一模板欄位：user_name、org_path、external_ref、roles。",
    "users.previewImport": "預覽匯入",
    "users.executeImport": "執行匯入",
    "users.previewSummary": "匯入預覽",
    "users.orgNodesToCreate": "待建立組織節點",
    "users.rolesToCreate": "待建立角色",
    "users.usersCreated": "建立使用者數",
    "users.usersUpdated": "更新使用者數",
    "users.keysCreated": "建立執行時金鑰數",
    "users.rootMapped": "組織路徑為空的使用者會掛載到 / 根節點下。",
    "users.importReady": "上傳檔案後先預覽，再確認組織變更、角色新增與受影響使用者。",
    "users.downloadTemplate": "下載模板",
    "users.templateGuide": "欄位說明",
    "users.templateGuideSummary": "請先下載模板並填寫，再上傳修改後的 Excel 檔。必填欄位不可刪除或改名。",
    "users.field": "欄位",
    "users.required": "是否必填",
    "users.format": "格式",
    "users.requirement": "要求說明",
    "users.templateField.user_name.format": "純文字，每列一個使用者姓名",
    "users.templateField.user_name.notes": "必填。這裡填寫管理員在控制台中應看到的姓名。",
    "users.templateField.org_path.format": "分層路徑，例如 Company/Finance/BI",
    "users.templateField.org_path.notes": "選填。留空時會放到根組織節點；缺少的層級會自動建立。",
    "users.templateField.external_ref.format": "穩定唯一識別，例如 EMP001 或 ext_user_123",
    "users.templateField.external_ref.notes": "必填。匯入流程會用它判斷是建立新使用者還是更新既有使用者。",
    "users.templateField.roles.format": "逗號分隔的角色名稱，例如 Analyst,Reviewer",
    "users.templateField.roles.notes": "選填。不存在的角色會在匯入時自動建立。",
    "users.importPlatform": "平台匯入",
    "users.importPlatformHint": "依平台填寫官方應用憑據。預覽或執行匯入時，閘道會直接呼叫對應平台的組織與使用者介面，不再要求你手動貼上回傳內容。",
    "users.platformGuide": "設定說明",
    "users.platformGuidePermissions": "所需權限",
    "users.platformGuideManifest": "在飛書開發者後台，進入「權限管理」->「批量導入/導出權限」，貼上以下 JSON：",
    "users.platformGuideManifestNote":
      "注意：新增權限後，必須建立並發布應用新版本，並在企業後台審批通過後，權限才會生效。",
    "users.platformAppId": "App ID",
    "users.platformAppSecret": "App Secret",
    "users.platformCorpId": "Corp ID",
    "users.platformCorpSecret": "通訊錄 Secret",
    "users.platformAppKey": "App Key",
    "users.platformRootDepartmentId": "根部門 ID",
    "users.platformRootDepartmentHint": "可選。用來把匯入範圍限制在某個組織分支；若要匯入整棵組織樹，就保留預設根部門 ID。",
    "users.platformFeishuStep1":
      "打開 open.feishu.cn，登入後進入開發者後台，建立企業自建應用。",
    "users.platformFeishuStep2":
      "左側選單進入「憑證與基礎資訊」，複製 App ID 和 App Secret，填入下方並保存設定。",
    "users.platformFeishuStep3":
      "左側選單進入「權限管理」，點擊「批量導入/導出權限」，貼上下方權限 JSON，並確認導入。",
    "users.platformFeishuStep4":
      "必須執行：左側選單進入「版本管理與發布」，建立版本（可用範圍設為所有員工），提交審核發布，並在飛書管理後台審批通過。注意：與釘釘不同，飛書所有權限必須經過發版並由企業管理員審批後才能生效，未發布則同步無法正常使用。",
    "users.platformFeishuPermissions":
      "必須開通 contact:contact.base:readonly、contact:department.base:readonly、contact:user.base:readonly、contact:user.employee_id:readonly。",
    "users.platformWecomStep1": "在企業微信準備可讀通訊錄的應用 Secret，並確認該應用具備讀取部門與成員的唯讀權限。",
    "users.platformWecomStep2": "填寫 Corp ID、通訊錄 Secret 和根部門 ID。若要匯入整棵樹，根部門 ID 預設填 1。",
    "users.platformWecomStep3": "先預覽匯入結果。閘道會自動把部門 ID 解析成完整組織路徑。",
    "users.platformWecomPermissions": "需要通訊錄唯讀權限，以及可呼叫部門與成員介面的通訊錄 Secret。",
    "users.platformDingtalkStep1": "在釘釘建立企業內部應用，並授予部門與成員唯讀權限。",
    "users.platformDingtalkStep2": "填寫 App Key、App Secret 和根部門 ID。若要匯入整棵樹，根部門 ID 預設填 1。",
    "users.platformDingtalkStep3": "先預覽。閘道會先拉取部門結構，再建立完整部門路徑並建立或更新使用者。",
    "users.platformDingtalkPermissions": "應用需要具備部門唯讀與成員唯讀權限。",
    "users.orgCreateRoot": "新增節點",
    "users.orgCreateSibling": "新增同級節點",
    "users.orgCreateChild": "新增子節點",
    "users.orgEdit": "編輯節點",
    "users.orgDelete": "刪除節點",
    "users.orgDeleteConfirm": "確認刪除這個組織節點？",
    "users.orgRootDeleteDisabled": "/ 根節點不能刪除。",
    "users.orgNodeTitle": "組織節點",
    "users.orgNodeMembers": "直屬成員",
    "users.orgNodeSelected": "目前選取節點",
    "users.importTabExcel": "Excel",
    "users.importTabFeishu": "飛書",
    "users.importTabWecom": "企業微信",
    "users.importTabDingtalk": "釘釘",
    "roles.directory": "角色目錄",
    "roles.summary": "供執行時授權使用的獨立目錄角色。",
    "roles.activeCount": "啟用角色數",
    "roles.emptyDescription": "尚未提供描述。",
    "roles.new": "新增",
    "roles.userCount": "關聯使用者數",
    "roles.linkedUsers": "查看關聯使用者",
    "roles.linkedUsersTitle": "{name} 的關聯使用者",
    "masking.fixedHint": "固定脫敏會固定回傳同一段替換文字。",
    "masking.partialHint": "局部脫敏會保留值的開頭和結尾可見部分。",
    "masking.noConfig": "目前的脫敏策略不需要額外設定。",
    "tag.relatedAssets": "關聯資源",
    "tag.relatedAssetsTitle": "{name} 的關聯資源",
    "tag.noLinkedAssets": "目前沒有資料資產關聯到這個標籤。",
    "onboarding.title": "管理員登入",
    "onboarding.description": "請輸入管理員 API 金鑰進入控制台。如果你還沒有初始化管理員金鑰，可以展開下方說明，依照自己的部署方式選擇命令。",
    "onboarding.inputLabel": "管理員 API 金鑰",
    "onboarding.inputPlaceholder": "輸入 init-admin 輸出的金鑰",
    "onboarding.continue": "登入控制台",
    "onboarding.methodsTitle": "初始化管理員 API 金鑰",
    "onboarding.method.python": "原生 Python",
    "onboarding.method.pythonDescription": "適合已經在原生 Python 環境中安裝專案的部署方式。",
    "onboarding.method.uv": "uv",
    "onboarding.method.uvDescription": "適合透過 uv 管理依賴、命令與本地開發流程的部署方式。",
    "onboarding.method.docker": "Docker",
    "onboarding.method.dockerDescription": "適合已經透過 Docker Compose 啟動後端容器的部署方式。",
    "onboarding.authErrorTitle": "認證失敗",
    "mcp.summaryTitle": "遠端 MCP 接入位址",
    "mcp.summaryDescription": "外部 MCP 客戶端應為每位使用者使用各自唯一的 runtime API Key。ADG 會根據該金鑰綁定的使用者自動派生執行期身份。",
    "mcp.serverUrl": "MCP 服務位址",
    "mcp.toolUrl": "補充普通 HTTP 工具位址",
    "mcp.transport": "傳輸方式",
    "mcp.transportValue": "Streamable HTTP",
    "mcp.authMode": "驗證方式",
    "mcp.authModeValue": "在每一個 MCP 請求上透過 {header} 標頭傳入 runtime scope 的 API Key。",
    "mcp.apiKeyHeader": "API 金鑰標頭",
    "mcp.tools": "工具清單",
    "mcp.platformsTitle": "客戶端接入範例",
    "mcp.platformsDescription": "依照你正在使用的 AI Agent 平台挑選設定方式，直接複製對應範例即可。",
    "mcp.notesTitle": "接入說明",
    "mcp.note.runtimeKey": "這裡必須使用每位使用者自己的 runtime scope API Key；只有 admin scope 的金鑰不能呼叫執行期 MCP 工具。",
    "mcp.note.identity": "執行期身份、組織歸屬與角色會依照該 API Key 綁定的使用者自動派生。",
    "mcp.note.reload": "修改本地設定檔之後，請重新啟動客戶端，或重新載入 MCP 設定。",
    "mcp.platform.codex.title": "Codex App",
    "mcp.platform.codex.summary": "在 ~/.codex/config.toml 裡註冊遠端 MCP 服務，並透過 HTTP Header 傳入目前登入使用者自己的 runtime API Key。",
    "mcp.platform.codex.step1": "在執行 Codex 的機器上打開 ~/.codex/config.toml。",
    "mcp.platform.codex.step2": "貼上下方 TOML 設定，並把環境變數指向目前使用者唯一的 runtime API Key 來源。",
    "mcp.platform.codex.step3": "儲存後重新啟動 Codex，或重新載入 MCP servers。",
    "mcp.platform.claude-code.title": "Claude Code",
    "mcp.platform.claude-code.summary": "Claude Code 既支援透過 JSON 直接匯入遠端 MCP，也支援專案層級的 .mcp.json 設定檔。",
    "mcp.platform.claude-code.step1": "想快速匯入就直接執行 CLI 範例；想做專案共用就把 JSON 範例寫入專案根目錄的 .mcp.json。",
    "mcp.platform.claude-code.step2": "啟動 Claude Code 之前，先把目前使用者唯一的 runtime API Key 放進環境變數。",
    "mcp.platform.claude-code.step3": "進入 Claude Code 後執行 /mcp，確認服務在線並檢查驗證狀態。",
    "mcp.platform.trae.title": "Trae",
    "mcp.platform.trae.summary": "Trae 可以在設定面板中手動新增 MCP，也可以從工作區層級的 .trae/mcp.json 自動匯入。",
    "mcp.platform.trae.step1": "打開 Settings > MCP，選擇手動設定，並在介面中選用 Streamable HTTP。",
    "mcp.platform.trae.step2": "把下面的 JSON 設定貼進去，或把相同內容儲存到專案根目錄的 .trae/mcp.json。",
    "mcp.platform.trae.step3": "重新打開 MCP 面板，或重新啟動 Trae，讓新服務與工具列表生效。",
    "mcp.platform.mcporter.title": "mcporter",
    "mcp.platform.mcporter.summary": "mcporter 可以從自己的 JSONC 設定載入遠端 MCP 服務，之後在 CLI 與腳本中重複使用同一套服務定義。",
    "mcp.platform.mcporter.step1": "在專案中建立 config/mcporter.json；如果想全域重用，也可以使用 ~/.mcporter/mcporter.json。",
    "mcp.platform.mcporter.step2": "貼上下方 JSON 設定，並把目前使用者唯一的 runtime API Key 存到 ADG_USER_RUNTIME_KEY 環境變數裡。",
    "mcp.platform.mcporter.step3": "執行 mcporter list adg，確認服務已連通並查看自動匯入的工具簽名。",
    "mcp.tool.list_datasources": "列出目前執行期身份可見的資料源。",
    "mcp.tool.list_tags": "列出目前執行期身份可見的治理標籤。",
    "mcp.tool.list_resources": "列出某個資料源下目前身份可讀的資源。",
    "mcp.tool.list_resources_by_tag": "依一個或多個標籤名稱查找目前身份可讀的資源。",
    "mcp.tool.describe_resource": "查看單一資源及其目前可見欄位的詳細資訊。",
    "mcp.tool.preview_resource": "在策略與脫敏生效後預覽單一資源的資料列。",
    "mcp.tool.execute_query": "在宣告資源範圍內執行唯讀 SQL 查詢。",
    "option.active": "啟用",
    "option.disabled": "停用",
    "option.all": "全員",
    "option.allow": "允許",
    "option.deny": "拒絕",
    "option.allowed": "允許",
    "option.denied": "拒絕",
    "option.user": "使用者",
    "option.role": "角色",
    "option.fixed": "固定替換",
    "option.partial": "部分遮罩",
    "option.hash": "雜湊",
    "option.reversible": "可逆加密",
    "option.postgres": "Postgres",
    "option.mysql": "MySQL",
    "option.doris": "Doris",
    "option.database": "資料庫",
    "option.schema": "Schema",
    "option.relational_table": "資料表",
    "option.relational_view": "檢視",
    "column.id": "ID",
    "column.datasource_id": "資料來源",
    "column.datasource_label": "資料來源",
    "column.datasource_count": "資料來源數量",
    "column.resource_id": "資源",
    "column.resource_label": "資源",
    "column.resource_count": "資源數量",
    "column.api_key_id": "API 金鑰",
    "column.user_id": "使用者 ID",
    "column.user_name": "使用者",
    "column.user_org_path": "所屬組織",
    "column.name": "名稱",
    "column.type": "類型",
    "column.datasource_kind": "資料來源類型",
    "column.config": "設定",
    "column.status": "狀態",
    "column.created_at": "建立時間",
    "column.updated_at": "更新時間",
    "column.kind": "類型",
    "column.path": "路徑",
    "column.display_name": "顯示名稱",
    "column.query_language": "查詢語言",
    "column.scanned_at": "掃描時間",
    "column.category": "分類",
    "column.description": "描述",
    "column.subject_type": "主體類型",
    "column.subject_id": "主體",
    "column.subject_label": "主體",
    "column.effect": "效果",
    "column.action": "操作",
    "column.tag_id": "標籤 ID",
    "column.tag_name": "標籤名稱",
    "column.tag_count": "標籤數量",
    "column.priority": "優先順序",
    "column.field_name": "欄位",
    "column.allow_decrypt": "允許解密",
    "column.strategy": "策略",
    "column.subject": "主體",
    "column.scopes": "權限範圍",
    "column.expires_at": "到期時間",
    "column.event_type": "事件類型",
    "column.decision": "決策",
    "column.reason": "原因",
    "column.resource_ids": "資源",
    "column.query_id": "查詢 ID",
    "column.data_type": "資料類型",
    "column.nullable": "可為空",
    "column.ordinal_position": "位置",
    "column.metadata": "中繼資料",
    "column.external_ref": "外部識別",
    "column.org_path": "組織路徑",
    "column.role_names": "角色",
    "column.actions": "操作",
    "option.metadata_discovery": "中繼資料探索",
    "option.resource_preview": "資源預覽",
    "option.query_execution": "查詢執行",
    "option.permission_rejected": "權限拒絕",
    "option.audit_sql_view": "查看稽核 SQL",
    "option.decryption": "資料解密",
    "option.query_allowed": "查詢放行"
  }
} as const;

type TranslationKey = keyof (typeof translations)["en-US"];
type I18nContextValue = {
  /** Currently selected console language. */
  language: Language;
  /** Persist and apply a new console language. */
  setLanguage: (language: Language) => void;
  /** Translate a key and interpolate optional named parameters. */
  t: (key: TranslationKey, params?: TranslationParams) => string;
};

const I18nContext = React.createContext<I18nContextValue | null>(null);

type FieldConfig = {
  /** Backend payload field name used by Ant Design forms. */
  name: string;
  label: TranslationKey;
  input?: "text" | "textarea" | "number" | "tags" | "select" | "resource-select";
  required?: boolean;
  options?: string[];
  resourceOptions?: AnyRecord[];
  loading?: boolean;
};

const antdLocales: Record<Language, typeof zhCN> = {
  "zh-CN": zhCN,
  "zh-TW": zhTW,
  "en-US": enUS
};

const pages: Array<{ key: PageKey; labelKey: TranslationKey; icon: React.ReactNode }> = [
  { key: "overview", labelKey: "nav.overview", icon: <ClusterOutlined /> },
  { key: "users", labelKey: "nav.users", icon: <TeamOutlined /> },
  { key: "roles", labelKey: "nav.roles", icon: <IdcardOutlined /> },
  { key: "datasources", labelKey: "nav.datasources", icon: <DatabaseOutlined /> },
  { key: "tags", labelKey: "nav.tags", icon: <TagsOutlined /> },
  { key: "policies", labelKey: "nav.policies", icon: <SafetyOutlined /> },
  { key: "masking", labelKey: "nav.masking", icon: <LockOutlined /> },
  { key: "apiKeys", labelKey: "nav.apiKeys", icon: <KeyOutlined /> },
  { key: "audit", labelKey: "nav.audit", icon: <AuditOutlined /> },
  { key: "mcp", labelKey: "nav.mcp", icon: <ApiOutlined /> }
];

function getStoredLanguage(): Language {
  /** Prefer persisted language, then a supported browser language, otherwise English. */

  const stored = localStorage.getItem("adg.language");
  const browserLanguages =
    typeof navigator === "undefined"
      ? []
      : [...(navigator.languages || []), navigator.language].filter(Boolean);
  return resolveInitialLanguage(stored, browserLanguages);
}

function getStoredPage(): PageKey {
  /** Restore the last visited page when it still exists in the current navigation model. */

  const stored = localStorage.getItem("adg.page");
  return pages.some((item) => item.key === stored) ? (stored as PageKey) : "overview";
}

function translate(language: Language, key: TranslationKey, params: TranslationParams = {}) {
  /** Resolve a translation key and replace simple `{name}` placeholders. */

  let text: string = translations[language][key] || translations["en-US"][key] || key;
  for (const [name, value] of Object.entries(params)) {
    text = text.split(`{${name}}`).join(String(value));
  }
  return text;
}

function useI18n() {
  /** Read the i18n context and fail loudly if the provider is missing. */

  const context = React.useContext(I18nContext);
  if (!context) {
    throw new Error("I18n context is missing");
  }
  return context;
}

function optionLabel(value: string, t: I18nContextValue["t"]) {
  /** Translate known enum-like values while leaving custom values untouched. */

  const key = `option.${value}` as TranslationKey;
  return key in translations["en-US"] ? t(key) : value;
}

type PopconfirmAction = "confirm" | "delete" | "revoke";

function popconfirmButtonProps(t: I18nContextValue["t"], action: PopconfirmAction = "confirm") {
  /** Keep confirmation popovers localized and sized for text labels. */

  const okTextByAction: Record<PopconfirmAction, string> = {
    confirm: t("common.confirm"),
    delete: t("common.delete"),
    revoke: t("common.revoke"),
  };

  return {
    okText: okTextByAction[action],
    cancelText: t("common.cancel"),
    okButtonProps: { size: "middle" as const, danger: action !== "confirm" },
    cancelButtonProps: { size: "middle" as const },
  };
}

function columnLabel(key: string, t: I18nContextValue["t"]) {
  /** Translate known table column keys while preserving unknown backend fields. */

  const translationKey = `column.${key}` as TranslationKey;
  return translationKey in translations["en-US"] ? t(translationKey) : key;
}

async function readApiErrorMessage(response: Response) {
  /** Prefer FastAPI's JSON detail field over raw response text for operator-facing errors. */

  const fallback = response.statusText || `HTTP ${response.status}`;
  const body = await response.text();
  if (!body) return fallback;
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string" && parsed.detail.trim()) {
      return parsed.detail;
    }
  } catch {
    return body;
  }
  return body;
}

function useApi() {
  /** Keep the admin API key in component state only and attach it to every console request. */

  const [apiKey, setApiKey] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const saveApiKey = (value: string) => {
    setApiKey(value);
    setAuthError(null);
  };
  const validateAndSaveApiKey = async (value: string) => {
    const candidate = value.trim();
    if (!candidate) {
      saveApiKey("");
      return;
    }
    setValidating(true);
    try {
      await validateAdminApiKey(fetch, candidate);
      saveApiKey(candidate);
    } catch (error) {
      setApiKey("");
      setAuthError(error instanceof Error ? error.message : String(error));
    } finally {
      setValidating(false);
    }
  };
  const request = async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
    // The frontend talks to relative paths so Vite and production hosting can proxy them.
    const response = await fetch(path, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-ADG-API-Key": apiKey,
        ...(options.headers || {})
      }
    });
    if (!response.ok) {
      const message = await readApiErrorMessage(response);
      if (response.status === 401 || response.status === 403) {
        setAuthError(message);
      }
      throw new Error(message);
    }
    setAuthError(null);
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  };
  return { apiKey, authError, validating, saveApiKey, validateAndSaveApiKey, request };
}

function useData<T>(
  loader: (page: PageRequest) => Promise<T | PaginatedResponse<unknown>>,
  deps: React.DependencyList,
  options: { paginated?: boolean; defaultLimit?: number } = {},
) {
  /** Load async table/detail data with a reload function and simple error state. */

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPageState] = useState<PageRequest>({
    limit: options.defaultLimit ?? DEFAULT_PAGE_LIMIT,
    offset: 0,
  });
  const [pageMeta, setPageMeta] = useState<Omit<PaginatedResponse<unknown>, "items"> | null>(null);
  const reload = () => {
    setLoading(true);
    setError(null);
    loader(page)
      .then((payload) => {
        if (isPaginatedResponse<unknown>(payload)) {
          setData(payload.items as T);
          setPageMeta({ total: payload.total, limit: payload.limit, offset: payload.offset });
        } else {
          setData(payload as T);
          setPageMeta(null);
        }
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  };
  useEffect(reload, [...deps, page.limit, page.offset]);
  const setPage = (limit: number, offset: number) => {
    setPageState({ limit, offset });
  };
  const pagination = options.paginated && pageMeta
    ? { ...pageMeta, items: [], setPage }
    : null;
  return { data, loading, error, reload, pagination };
}

function useViewportBreakpoint(maxWidth: number) {
  /** Return whether the current viewport width is at or below one responsive breakpoint. */

  const read = () => (typeof window === "undefined" ? false : window.innerWidth <= maxWidth);
  const [matches, setMatches] = useState(read);

  useEffect(() => {
    let frameId: number | null = null;
    const onResize = () => {
      if (frameId !== null) {
        window.cancelAnimationFrame(frameId);
      }
      frameId = window.requestAnimationFrame(() => {
        frameId = null;
        setMatches(read());
      });
    };
    window.addEventListener("resize", onResize);
    return () => {
      if (frameId !== null) {
        window.cancelAnimationFrame(frameId);
      }
      window.removeEventListener("resize", onResize);
    };
  }, [maxWidth]);

  return matches;
}

function App() {
  /** Configure Ant Design theming and provide translation state to the console. */

  const [language, setLanguageState] = useState<Language>(getStoredLanguage);
  const setLanguage = (value: Language) => {
    localStorage.setItem("adg.language", value);
    setLanguageState(value);
  };
  const t = (key: TranslationKey, params?: TranslationParams) => translate(language, key, params);
  return (
    <ConfigProvider
      locale={antdLocales[language]}
      button={{ autoInsertSpace: false }}
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#12766f",
          colorInfo: "#12766f",
          colorSuccess: "#168a5b",
          colorWarning: "#b7791f",
          colorError: "#b42318",
          borderRadius: 6,
          fontFamily: "Segoe UI, ui-sans-serif, system-ui, sans-serif",
          fontSize: 13,
          colorBgLayout: "#eef3f1",
          colorBgContainer: "#ffffff",
          colorText: "#17211f",
          colorTextSecondary: "#61716c",
          colorBorder: "#d7e1de"
        }
      }}
    >
      <AntApp>
        <I18nContext.Provider value={{ language, setLanguage, t }}>
          <ConsoleApp />
        </I18nContext.Provider>
      </AntApp>
    </ConfigProvider>
  );
}

function ConsoleApp() {
  /** Render the fixed shell, navigation, language switcher, and active page. */

  const { language, setLanguage, t } = useI18n();
  const [page, setPage] = useState<PageKey>(getStoredPage);
  const [catalogJumpTarget, setCatalogJumpTarget] = useState<CatalogJumpTarget | null>(null);
  const [draftApiKey, setDraftApiKey] = useState("");
  const [compactNavOpen, setCompactNavOpen] = useState(false);
  const showCompactNav = useViewportBreakpoint(920);
  const api = useApi();
  const showOnboarding = !api.apiKey || Boolean(api.authError);
  const navigationItems = pages.map((item) => ({
    key: item.key,
    icon: item.icon,
    label: t(item.labelKey)
  }));
  const currentPageTitle = showOnboarding
    ? t("onboarding.title")
    : t(pages.find((item) => item.key === page)?.labelKey || "nav.overview");

  useEffect(() => {
    setDraftApiKey(api.apiKey);
  }, [api.apiKey, api.authError]);

  useEffect(() => {
    localStorage.setItem("adg.page", page);
  }, [page]);

  const openCatalogNode = (target: CatalogJumpTarget) => {
    setPage("datasources");
    setCatalogJumpTarget(target);
  };
  if (showOnboarding) {
    return (
      <AdminOnboarding
        apiKey={draftApiKey}
        authError={api.authError}
        validating={api.validating}
        onApiKeyChange={setDraftApiKey}
        onContinue={() => void api.validateAndSaveApiKey(draftApiKey)}
        brandLabel={t("brand.productName")}
        languageControl={
          <LanguageSwitcher
            className="language-select language-select-login"
            label={t("topbar.switchLanguage")}
            value={language}
            options={languageOptions}
            onChange={setLanguage}
          />
        }
        copy={{
          title: t("onboarding.title"),
          description: t("onboarding.description"),
          inputLabel: t("onboarding.inputLabel"),
          inputPlaceholder: t("onboarding.inputPlaceholder"),
          continueLabel: t("onboarding.continue"),
          methodsTitle: t("onboarding.methodsTitle"),
          methods: [
            {
              key: "python",
              label: t("onboarding.method.python"),
              description: t("onboarding.method.pythonDescription"),
              commandValue: "python -m adg.control_plane.bootstrap --database-url sqlite:///./data/adg-control-plane.db",
            },
            {
              key: "uv",
              label: t("onboarding.method.uv"),
              description: t("onboarding.method.uvDescription"),
              commandValue: "uv run --extra dev init-admin --database-url sqlite:///./data/adg-control-plane.db",
            },
            {
              key: "docker",
              label: t("onboarding.method.docker"),
              description: t("onboarding.method.dockerDescription"),
              commandValue: "docker compose exec backend init-admin",
            },
          ],
          authErrorTitle: t("onboarding.authErrorTitle"),
        }}
      />
    );
  }
  return (
    <Layout className="shell">
      <Layout.Sider width={248} className="sider">
        <div className="brand">
            <span className="brand-mark">ADG</span>
            <span>
              <span className="brand-name">AI Data Access Gateway</span>
              <span className="brand-subtitle">{t("brand.controlPlane")}</span>
            </span>
          </div>
          <Menu
            mode="inline"
            selectedKeys={[page]}
            items={navigationItems}
            onClick={({ key }) => setPage(key as PageKey)}
          />
      </Layout.Sider>
      <Layout>
        <Layout.Header className="topbar">
          <div className="topbar-page">
            <Typography.Text className="page-kicker">{t("topbar.kicker")}</Typography.Text>
            <div className="page-title-row">
              {showCompactNav ? (
                <Button
                  className="compact-nav-trigger compact-nav-trigger-inline"
                  aria-label={t("topbar.openNavigation")}
                  icon={<MenuOutlined />}
                  onClick={() => setCompactNavOpen(true)}
                />
              ) : null}
              <Typography.Title level={3} className="page-title">
                {currentPageTitle}
              </Typography.Title>
            </div>
          </div>
          <div className="topbar-actions">
            <LanguageSwitcher
              className="language-select language-select-header"
              label={t("topbar.switchLanguage")}
              value={language}
              options={languageOptions}
              onChange={setLanguage}
            />
            <ApiKeyField
              label={t("topbar.apiKey")}
              value={showOnboarding ? draftApiKey : api.apiKey}
              showLabel={t("topbar.showApiKey")}
              hideLabel={t("topbar.hideApiKey")}
              onChange={(value) => {
                if (showOnboarding) {
                  setDraftApiKey(value);
                } else {
                  api.saveApiKey(value);
                }
              }}
            />
          </div>
        </Layout.Header>
        <Layout.Content className="content">
          <Page
            page={page}
            api={api}
            catalogJumpTarget={catalogJumpTarget}
            onCatalogJumpHandled={() => setCatalogJumpTarget(null)}
            onOpenCatalogNode={openCatalogNode}
          />
        </Layout.Content>
      </Layout>
      <Drawer
        title={t("topbar.navigation")}
        placement="left"
        width={280}
        className="compact-nav-drawer"
        open={showCompactNav && compactNavOpen}
        onClose={() => setCompactNavOpen(false)}
      >
        <Menu
          mode="inline"
          selectedKeys={[page]}
          items={navigationItems}
          onClick={({ key }) => {
            setPage(key as PageKey);
            setCompactNavOpen(false);
          }}
        />
      </Drawer>
    </Layout>
  );
}

function Page({
  page,
  api,
  catalogJumpTarget,
  onCatalogJumpHandled,
  onOpenCatalogNode,
}: {
  page: PageKey;
  api: ReturnType<typeof useApi>;
  catalogJumpTarget: CatalogJumpTarget | null;
  onCatalogJumpHandled: () => void;
  onOpenCatalogNode: (target: CatalogJumpTarget) => void;
}) {
  /** Route the selected navigation key to its console page component. */

  if (page === "overview") return <Overview api={api} />;
  if (page === "users") return <UsersPage api={api} />;
  if (page === "roles") return <RolesPage api={api} />;
  if (page === "datasources") {
    return (
      <Datasources
        api={api}
        jumpTarget={catalogJumpTarget}
        onJumpHandled={onCatalogJumpHandled}
      />
    );
  }
  if (page === "tags") return <Tags api={api} onOpenCatalogNode={onOpenCatalogNode} />;
  if (page === "policies") return <Policies api={api} />;
  if (page === "masking") return <Masking api={api} />;
  if (page === "apiKeys") return <ApiKeys api={api} />;
  if (page === "audit") return <AuditEventsPage api={api} />;
  return <McpSetup api={api} />;
}

function Overview({ api }: { api: ReturnType<typeof useApi> }) {
  /** Show a compact operational summary for the current control-plane data. */

  const { t } = useI18n();
  const datasources = useData<AnyRecord[]>(() => api.request("/admin/datasources"), [api.apiKey]);
  const resources = useData<AnyRecord[]>((page) => api.request(paginatedPath("/admin/resources", page)), [api.apiKey], { paginated: true });
  const audit = useData<AnyRecord[]>((page) => api.request(paginatedPath("/admin/audit-events", page)), [api.apiKey], { paginated: true });
  return (
    <div className="workspace">
      <div className="stats">
        <Statistic title={t("stats.datasources")} value={datasources.data?.length || 0} />
        <Statistic title={t("stats.resources")} value={resources.pagination?.total ?? resources.data?.length ?? 0} />
        <Statistic title={t("stats.audit")} value={audit.pagination?.total ?? audit.data?.length ?? 0} />
      </div>
    </div>
  );
}

function UsersPage({ api }: { api: ReturnType<typeof useApi> }) {
  /** Split-pane directory workspace with org tree, user list, details, and import actions. */

  const { message: messageApi, modal } = AntApp.useApp();
  const { t } = useI18n();
  const compactDirectoryLayout = useViewportBreakpoint(1280);
  const orgNodesState = useData<AnyRecord[]>(() => api.request("/admin/org-nodes"), [api.apiKey]);
  const rolesState = useData<AnyRecord[]>(() => api.request("/admin/roles"), [api.apiKey]);
  const usersState = useData<DirectoryUserRecord[]>(
    async () => {
      try {
        return await api.request("/admin/users");
      } catch {
        return [];
      }
    },
    [api.apiKey],
  );
  const [sessionUsers, setSessionUsers] = useState<DirectoryUserRecord[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [importPreview, setImportPreview] = useState<AnyRecord | null>(null);
  const [importFileName, setImportFileName] = useState("");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importSource, setImportSource] = useState<"excel" | ImportPlatformKey>("excel");
  const [orgNodeModalOpen, setOrgNodeModalOpen] = useState(false);
  const [editingOrgNodeId, setEditingOrgNodeId] = useState<string | null>(null);
  const [orgNodeParentId, setOrgNodeParentId] = useState<string | null>(null);
  const [createForm] = Form.useForm();
  const [importForm] = Form.useForm();
  const [orgNodeForm] = Form.useForm();
  const orgNodes = orgNodesState.data || [];
  const roles = rolesState.data || [];
  const users = mergeDirectoryUsers(usersState.data || [], sessionUsers, orgNodes, roles);
  const importTemplateRows = directoryImportTemplateFields.map((field) => ({
    field: field.field,
    required: field.required,
    format: t(`users.templateField.${field.field}.format` as TranslationKey),
    notes: t(`users.templateField.${field.field}.notes` as TranslationKey),
  }));
  const orgTree = buildOrgTree(orgNodes);
  const rootOrgNode = orgNodes.find((node) => String(node.path || "") === "") || null;
  const selectedOrgNode = selectedOrgId
    ? orgNodes.find((node) => String(node.id) === selectedOrgId) || null
    : null;
  const orgDescendantIds = selectedOrgId ? collectOrgDescendantIds(orgNodes, selectedOrgId) : null;
  const filteredUsers = orgDescendantIds
    ? users.filter((user) => user.org_node_id && orgDescendantIds.has(String(user.org_node_id)))
    : users;
  const selectedUser =
    filteredUsers.find((user) => (user.id || user.user_id) === selectedUserId)
    || users.find((user) => (user.id || user.user_id) === selectedUserId)
    || filteredUsers[0]
    || null;

  useEffect(() => {
    if (selectedUser && selectedUserId !== (selectedUser.id || selectedUser.user_id || null)) {
      setSelectedUserId(String(selectedUser.id || selectedUser.user_id || ""));
    }
  }, [selectedUser, selectedUserId]);

  const reloadDirectory = () => {
    orgNodesState.reload();
    rolesState.reload();
    usersState.reload();
  };

  const replaceSessionUser = (nextUser: DirectoryUserRecord) => {
    const nextId = String(nextUser.id || nextUser.user_id || "");
    setSessionUsers((current) => mergeDirectoryUsers(
      current.filter((user) => String(user.id || user.user_id || "") !== nextId),
      [nextUser],
      orgNodes,
      roles,
    ));
  };

  const removeSessionUser = (userId: string) => {
    setSessionUsers((current) => current.filter((user) => String(user.id || user.user_id || "") !== userId));
  };

  const closeUserDrawer = () => {
    setCreateOpen(false);
    setEditingUserId(null);
    createForm.resetFields();
  };

  const openCreateUser = () => {
    setEditingUserId(null);
    createForm.setFieldsValue({
      name: "",
      externalRef: "",
      orgNodeId: undefined,
      roleIds: [],
      status: "active",
    });
    setCreateOpen(true);
  };

  const openEditUser = (user: DirectoryUserRecord | null = selectedUser) => {
    const userId = String(user?.id || user?.user_id || "");
    if (!user || !userId) return;
    setEditingUserId(userId);
    createForm.setFieldsValue({
      name: user.name,
      externalRef: user.external_ref,
      orgNodeId: user.org_node_id || undefined,
      roleIds: user.role_ids || [],
      status: user.status || "active",
    });
    setCreateOpen(true);
  };

  const openCreateOrgNode = (
    mode: "root" | "sibling" | "child" | "edit",
    node: AnyRecord | null = selectedOrgNode,
  ) => {
    if (mode !== "root" && !node) return;
    if (mode === "edit" && node) {
      setEditingOrgNodeId(String(node.id));
      setOrgNodeParentId(String(node.parent_id || "") || null);
      orgNodeForm.setFieldsValue({
        name: node.name,
        code: node.code || "",
        status: node.status,
      });
    } else {
      setEditingOrgNodeId(null);
      if (mode === "child" && node) {
        setOrgNodeParentId(String(node.id));
      } else if (mode === "sibling" && node) {
        setOrgNodeParentId(node.parent_id ? String(node.parent_id) : (rootOrgNode?.id ? String(rootOrgNode.id) : null));
      } else {
        setOrgNodeParentId(rootOrgNode?.id ? String(rootOrgNode.id) : null);
      }
      orgNodeForm.setFieldsValue({
        name: "",
        code: "",
        status: "active",
      });
    }
    setOrgNodeModalOpen(true);
  };

  const saveOrgNode = async () => {
    const values = await orgNodeForm.validateFields();
    const payload = {
      name: String(values.name || "").trim(),
      code: String(values.code || "").trim() || null,
      status: String(values.status || "active"),
    };
    if (editingOrgNodeId) {
      await api.request(`/admin/org-nodes/${editingOrgNodeId}`, {
        method: "PATCH",
        body: JSON.stringify({ ...payload, parent_id: orgNodeParentId }),
      });
    } else {
      await api.request("/admin/org-nodes", {
        method: "POST",
        body: JSON.stringify({
          ...payload,
          parent_id: orgNodeParentId,
        }),
      });
    }
    setOrgNodeModalOpen(false);
    setEditingOrgNodeId(null);
    setOrgNodeParentId(null);
    orgNodeForm.resetFields();
    reloadDirectory();
    messageApi.success(t("common.saved"));
  };

  const deleteOrgNode = async (node: AnyRecord | null = selectedOrgNode) => {
    if (!node) return;
    if (String(node.path || "") === "") {
      messageApi.warning(t("users.orgRootDeleteDisabled"));
      return;
    }
    await api.request(`/admin/org-nodes/${node.id}`, { method: "DELETE" });
    setSelectedOrgId((current) => (current === String(node.id) ? null : current));
    reloadDirectory();
    messageApi.success(t("common.deleted"));
  };

  const orgTreeData = toOrgTreeData(orgTree, t, {
    onCreateNode: (node) => openCreateOrgNode("root", node),
    onCreateSibling: (node) => openCreateOrgNode("sibling", node),
    onCreateChild: (node) => openCreateOrgNode("child", node),
    onEditNode: (node) => openCreateOrgNode("edit", node),
    onDeleteNode: (node) => void deleteOrgNode(node),
    onSelectNode: (node) => setSelectedOrgId(node.key),
  });

  const saveUser = async () => {
    const values = await createForm.validateFields();
    const payload = buildUserCreatePayload(values);
    if (editingUserId) {
      const updated = await api.request<DirectoryUserRecord>(`/admin/users/${editingUserId}`, {
        method: "PATCH",
        body: JSON.stringify({
          ...payload,
          status: String(values.status || "active"),
        }),
      });
      replaceSessionUser({
        ...updated,
        id: String(updated.id || editingUserId),
        user_id: updated.user_id ? String(updated.user_id) : undefined,
        org_node_id: updated.org_node_id ? String(updated.org_node_id) : null,
        role_ids: Array.isArray(updated.role_ids) ? updated.role_ids.map(String) : [],
        role_names: Array.isArray(updated.role_names) ? updated.role_names.map(String) : [],
        status: String(updated.status || "active"),
      });
      setSelectedUserId(String(updated.id || editingUserId));
      closeUserDrawer();
      reloadDirectory();
      messageApi.success(t("common.saved"));
      return;
    }

    const created = await api.request<AnyRecord>("/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const roleNames = roles
      .filter((role) => payload.role_ids.includes(String(role.id)))
      .map((role) => String(role.name));
    replaceSessionUser({
      id: String(created.id),
      name: String(created.name),
      external_ref: String(created.external_ref),
      org_node_id: created.org_node_id ? String(created.org_node_id) : null,
      org_path: pathForOrgNode(orgNodes, created.org_node_id),
      role_ids: payload.role_ids,
      role_names: roleNames,
      status: String(created.status || "active"),
    });
    setSelectedUserId(String(created.id));
    closeUserDrawer();
    reloadDirectory();
    modal.info({
      title: t("users.runtimeKey"),
      content: <Typography.Text copyable>{String(created.api_key)}</Typography.Text>,
    });
  };

  const deleteUser = async (user: DirectoryUserRecord | null = selectedUser) => {
    const userId = String(user?.id || user?.user_id || "");
    if (!user || !userId) return;
    await api.request(`/admin/users/${userId}`, { method: "DELETE" });
    removeSessionUser(userId);
    setSelectedUserId((current) => (current === userId ? null : current));
    reloadDirectory();
    messageApi.success(t("common.deleted"));
  };

  const resetRuntimeKey = async () => {
    if (!selectedUser?.id && !selectedUser?.user_id) return;
    const response = await api.request<AnyRecord>(
      `/admin/users/${selectedUser.id || selectedUser.user_id}/reset-key`,
      { method: "POST" },
    );
    modal.info({
      title: t("users.latestKey"),
      content: <Typography.Text copyable>{String(response.api_key)}</Typography.Text>,
    });
  };

  const previewImport = async (mode: "preview" | "execute") => {
    const values = await importForm.validateFields();
    setPreviewLoading(true);
    try {
      let result: AnyRecord;
      if (importSource === "excel") {
        if (!importFile) {
          messageApi.error(t("users.importReady"));
          return;
        }
        const rows = await parseDirectoryRowsFromFile(importFile);
        const payload = buildDirectoryImportPayload(rows, values.delimiter);
        const endpoint = mode === "execute"
          ? "/admin/users/imports/excel/execute"
          : "/admin/users/imports/excel/preview";
        result = await api.request<AnyRecord>(endpoint, {
          method: "POST",
          body: JSON.stringify(payload),
        });
      } else {
        result = await api.request<AnyRecord>(`/admin/users/importers/${importSource}/pull`, {
          method: "POST",
          body: JSON.stringify({
            mode,
            config: buildDirectoryImporterConfig(importSource, values),
          }),
        });
      }
      setImportPreview(result);
      if (mode === "execute") {
        const executedUsers = Array.isArray(result.users)
          ? result.users.map((user) => ({
              id: user.user_id ? String(user.user_id) : undefined,
              user_id: user.user_id ? String(user.user_id) : undefined,
              name: String(user.user_name || ""),
              external_ref: String(user.external_ref || ""),
              org_node_id: orgNodeIdForPath(orgNodes, user.org_path),
              org_path: user.org_path ? String(user.org_path) : null,
              role_ids: roleIdsForNames(roles, Array.isArray(user.roles) ? user.roles.map(String) : []),
              role_names: Array.isArray(user.roles) ? user.roles.map(String) : [],
              status: "active",
            }))
          : [];
        setSessionUsers((current) => mergeDirectoryUsers(current, executedUsers, orgNodes, roles));
        reloadDirectory();
        setImportOpen(false);
        setImportPreview(null);
        setImportFile(null);
        setImportFileName("");
        messageApi.success(t("common.saved"));
      }
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : String(error));
    } finally {
      setPreviewLoading(false);
    }
  };

  return (
    <section className={`directory-workspace${compactDirectoryLayout ? " directory-workspace-compact" : ""}`}>
      <div className="directory-tree-pane panel">
        <div className="panel-head">
          <Typography.Title level={4}>{t("users.organizationTree")}</Typography.Title>
        </div>
        <div className="directory-tree-body">
          <Tree
            blockNode
            defaultExpandAll
            treeData={orgTreeData}
            selectedKeys={selectedOrgId ? [selectedOrgId] : []}
            onSelect={(keys) => setSelectedOrgId(String(keys[0] || ""))}
          />
        </div>
      </div>
      <div className="directory-users-pane">
        <div className="directory-toolbar">
          <div className="directory-toolbar-copy">
            <Typography.Title level={4}>{t("users.directory")}</Typography.Title>
            <Typography.Paragraph>{t("users.rootMapped")}</Typography.Paragraph>
          </div>
          <Space wrap>
            <Button icon={<PlusOutlined />} type="primary" onClick={openCreateUser}>
              {t("users.new")}
            </Button>
            <Button icon={<InboxOutlined />} onClick={() => setImportOpen(true)}>
              {t("users.importExcel")}
            </Button>
          </Space>
        </div>
        <div className={`directory-main${compactDirectoryLayout ? " directory-main-compact" : ""}`}>
          <section className="panel directory-list-panel">
            <div className="panel-head">
              <Typography.Title level={4}>{t("users.directory")}</Typography.Title>
              <Tag>{t("common.rows", { count: filteredUsers.length })}</Tag>
            </div>
            {usersState.error ? <Alert type="warning" message={String(usersState.error)} /> : null}
            <Table
              size="small"
              rowKey={(row) => row.id || row.user_id || row.external_ref}
              dataSource={filteredUsers}
              pagination={{ pageSize: 7 }}
              onRow={(row) => ({
                onClick: () => setSelectedUserId(String(row.id || row.user_id || row.external_ref)),
              })}
              columns={[
                { title: columnLabel("name", t), dataIndex: "name", key: "name", width: 160, ellipsis: true },
                { title: columnLabel("external_ref", t), dataIndex: "external_ref", key: "external_ref", width: 150, ellipsis: true },
                { title: columnLabel("org_path", t), dataIndex: "org_path", key: "org_path", width: 220, ellipsis: true },
                {
                  title: columnLabel("role_names", t),
                  dataIndex: "role_names",
                  key: "role_names",
                  width: 200,
                  render: (value: string[]) => (
                    <Space size={[6, 6]} wrap>
                      {(value || []).map((role) => <Tag key={role}>{role}</Tag>)}
                    </Space>
                  ),
                },
              ]}
              scroll={{ x: 760 }}
            />
          </section>
          <section className="panel directory-detail-panel">
            <div className="panel-head">
              <Typography.Title level={4}>{t("users.details")}</Typography.Title>
              <Space wrap>
                <Tag color="cyan">{selectedUser?.status || "active"}</Tag>
                <Button
                  aria-label={t("common.edit")}
                  icon={<EditOutlined />}
                  disabled={!selectedUser}
                  onClick={() => openEditUser()}
                >
                  {t("common.edit")}
                </Button>
                <Popconfirm
                  title={t("common.deleteConfirm", { title: selectedUser?.name || t("nav.users") })}
                  onConfirm={() => void deleteUser()}
                  disabled={!selectedUser}
                  {...popconfirmButtonProps(t, "delete")}
                >
                  <Button aria-label={t("common.delete")} icon={<DeleteOutlined />} disabled={!selectedUser}>
                    {t("common.delete")}
                  </Button>
                </Popconfirm>
                <Button
                  icon={<SyncOutlined />}
                  disabled={!selectedUser}
                  onClick={() => void resetRuntimeKey()}
                >
                  {t("users.resetKey")}
                </Button>
              </Space>
            </div>
            <div className="directory-detail-body">
              {selectedUser ? (
                <>
                  <Descriptions bordered column={1} size="small">
                    <Descriptions.Item label={t("field.name")}>{selectedUser.name}</Descriptions.Item>
                    <Descriptions.Item label={t("field.externalRef")}>{selectedUser.external_ref}</Descriptions.Item>
                    <Descriptions.Item label={t("field.orgNode")}>{selectedUser.org_path || "-"}</Descriptions.Item>
                    <Descriptions.Item label={t("field.roles")}>
                      <Space size={[6, 6]} wrap>
                        {selectedUser.role_names.length
                          ? selectedUser.role_names.map((role) => <Tag key={role}>{role}</Tag>)
                          : <Typography.Text type="secondary">-</Typography.Text>}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label={t("users.orgNodeMembers")}>
                      <Space size={[6, 6]} wrap>
                        {(Array.isArray(selectedOrgNode?.direct_user_names) ? selectedOrgNode?.direct_user_names : []).length
                          ? (selectedOrgNode?.direct_user_names || []).map((userName: string) => <Tag key={userName}>{userName}</Tag>)
                          : <Typography.Text type="secondary">-</Typography.Text>}
                      </Space>
                    </Descriptions.Item>
                  </Descriptions>
                  <div className="directory-runtime-panel">
                    <Typography.Text className="directory-runtime-label">{t("users.runtimeKey")}</Typography.Text>
                    <Typography.Paragraph>{t("users.generateKey")}</Typography.Paragraph>
                  </div>
                </>
              ) : (
                <Empty description={t("users.emptySelection")} />
              )}
            </div>
          </section>
        </div>
      </div>

      <Drawer
        title={editingUserId ? t("common.editTitle", { title: t("nav.users") }) : t("common.createTitle", { title: t("nav.users") })}
        open={createOpen}
        width={460}
        onClose={closeUserDrawer}
        extra={<Button type="primary" onClick={() => void saveUser()}>{t("common.save")}</Button>}
      >
        <Form form={createForm} layout="vertical" initialValues={{ roleIds: [], status: "active" }}>
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="externalRef" label={t("field.externalRef")} rules={[{ required: true }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="orgNodeId" label={t("field.orgNode")}>
            <Select
              allowClear
              showSearch
              placeholder={t("placeholder.orgNodeSearch")}
              options={orgNodes.map((node) => ({
                value: node.id,
                label: String(node.path || "") ? String(node.path) : "/",
              }))}
            />
          </Form.Item>
          <Form.Item name="roleIds" label={t("field.roles")}>
            <Select
              mode="multiple"
              placeholder={t("placeholder.roleSearch")}
              options={roles.map((role) => ({ value: role.id, label: role.name }))}
            />
          </Form.Item>
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={t("users.importTitle")}
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        footer={[
          <Button key="preview" loading={previewLoading} onClick={() => void previewImport("preview")}>
            {t("users.previewImport")}
          </Button>,
          <Button key="execute" type="primary" loading={previewLoading} onClick={() => void previewImport("execute")}>
            {t("users.executeImport")}
          </Button>,
        ]}
        width={880}
      >
        <Tabs
          destroyOnHidden
          activeKey={importSource}
          onChange={(value) => {
            setImportSource(value as "excel" | ImportPlatformKey);
            setImportPreview(null);
          }}
          items={[
            {
              key: "excel",
              label: t("users.importTabExcel"),
              children: (
                <div className={`directory-import-layout${compactDirectoryLayout ? " directory-import-layout-compact" : ""}`}>
                  <div className="directory-import-uploader">
                    <Space align="center" wrap>
                      <Typography.Text strong>{t("users.uploadFile")}</Typography.Text>
                      <Button
                        icon={<DownloadOutlined />}
                        href="/adg-user-import-template.xlsx"
                        target="_blank"
                      >
                        {t("users.downloadTemplate")}
                      </Button>
                    </Space>
                    <Typography.Paragraph>{t("users.importHint")}</Typography.Paragraph>
                    <Typography.Paragraph type="secondary">{t("users.templateGuideSummary")}</Typography.Paragraph>
                    <Table
                      size="small"
                      pagination={false}
                      rowKey="field"
                      dataSource={importTemplateRows}
                      columns={[
                        { title: t("users.field"), dataIndex: "field", key: "field", width: 120 },
                        { title: t("users.required"), dataIndex: "required", key: "required", width: 96, render: (value: boolean) => (value ? t("common.yes") : t("common.no")) },
                        { title: t("users.format"), dataIndex: "format", key: "format", width: 200 },
                        { title: t("users.requirement"), dataIndex: "notes", key: "notes" },
                      ]}
                    />
                    <Form form={importForm} layout="vertical" initialValues={{ delimiter: "/" }}>
                      <Form.Item name="delimiter" label={t("field.orgDelimiter")}>
                        <Input aria-label={t("field.orgDelimiter")} />
                      </Form.Item>
                    </Form>
                    <Upload.Dragger
                      multiple={false}
                      beforeUpload={(file) => {
                        setImportFile(file);
                        setImportFileName(file.name);
                        return false;
                      }}
                      showUploadList={false}
                      onRemove={() => {
                        setImportFile(null);
                        setImportFileName("");
                        setImportPreview(null);
                      }}
                    >
                      <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                      <p className="ant-upload-text">{t("users.dragFileHere")}</p>
                      <p className="ant-upload-hint">{importFileName || t("users.importReady")}</p>
                    </Upload.Dragger>
                  </div>
                  <ImportPreviewPanel importPreview={importPreview} importFileName={importFileName} t={t} />
                </div>
              ),
            },
            ...(["feishu", "wecom", "dingtalk"] as ImportPlatformKey[]).map((platform) => ({
              key: platform,
              label: t(`users.importTab${platform.charAt(0).toUpperCase()}${platform.slice(1)}` as TranslationKey),
              children: (
                <div className={`directory-import-layout${compactDirectoryLayout ? " directory-import-layout-compact" : ""}`}>
                  <ImportPlatformPanel
                    platform={platform}
                    form={importForm}
                    t={t}
                  />
                  <ImportPreviewPanel importPreview={importPreview} importFileName={t(`users.importTab${platform.charAt(0).toUpperCase()}${platform.slice(1)}` as TranslationKey)} t={t} />
                </div>
              ),
            })),
          ]}
        />
      </Modal>

      <Modal
        title={t("users.orgNodeTitle")}
        open={orgNodeModalOpen}
        onCancel={() => {
          setOrgNodeModalOpen(false);
          setEditingOrgNodeId(null);
          setOrgNodeParentId(null);
        }}
        onOk={() => void saveOrgNode()}
      >
        <Form form={orgNodeForm} layout="vertical">
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="code" label="Code">
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
        </Form>
      </Modal>
    </section>
  );
}

function RolesPage({ api }: { api: ReturnType<typeof useApi> }) {
  /** Editable role workspace with CRUD and linked-user inspection. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const state = useData<AnyRecord[]>(() => api.request("/admin/roles"), [api.apiKey]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<AnyRecord | null>(null);
  const [linkedUsersRole, setLinkedUsersRole] = useState<AnyRecord | null>(null);
  const [linkedUsers, setLinkedUsers] = useState<DirectoryUserRecord[]>([]);
  const [linkedUsersLoading, setLinkedUsersLoading] = useState(false);
  const [form] = Form.useForm();
  const activeRoles = (state.data || []).filter((role) => role.status === "active").length;

  const openCreate = () => {
    setEditingRole(null);
    form.setFieldsValue({ name: "", description: "", status: "active" });
    setEditorOpen(true);
  };

  const openEdit = (role: AnyRecord) => {
    setEditingRole(role);
    form.setFieldsValue({
      name: role.name,
      description: role.description || "",
      status: role.status || "active",
    });
    setEditorOpen(true);
  };

  const saveRole = async () => {
    const values = await form.validateFields();
    const payload = {
      name: String(values.name || "").trim(),
      description: String(values.description || "").trim() || null,
      status: String(values.status || "active"),
    };
    if (editingRole?.id) {
      await api.request(`/admin/roles/${editingRole.id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
    } else {
      await api.request("/admin/roles", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    }
    setEditorOpen(false);
    setEditingRole(null);
    form.resetFields();
    state.reload();
    messageApi.success(t("common.saved"));
  };

  const deleteRole = async (roleId: string) => {
    try {
      await api.request(`/admin/roles/${roleId}`, { method: "DELETE" });
      state.reload();
      messageApi.success(t("common.deleted"));
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : String(error));
    }
  };

  const openLinkedUsers = async (role: AnyRecord) => {
    setLinkedUsersRole(role);
    setLinkedUsersLoading(true);
    try {
      const users = await api.request<DirectoryUserRecord[]>(`/admin/roles/${role.id}/users`);
      setLinkedUsers(users);
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : String(error));
      setLinkedUsers([]);
    } finally {
      setLinkedUsersLoading(false);
    }
  };

  return (
    <section className="roles-workspace">
      <div className="stats">
        <Statistic title={t("roles.activeCount")} value={activeRoles} />
        <Statistic title={t("common.rows", { count: state.data?.length || 0 })} value={state.data?.length || 0} />
      </div>
      <section className="panel">
        <div className="panel-head">
          <div>
            <Typography.Title level={4}>{t("roles.directory")}</Typography.Title>
            <Typography.Text type="secondary">{t("roles.summary")}</Typography.Text>
          </div>
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            {t("roles.new")}
          </Button>
        </div>
        {state.error ? <Alert type="error" message={state.error} /> : (
          <Table
            size="small"
            rowKey="id"
            loading={state.loading}
            dataSource={state.data || []}
            pagination={false}
            scroll={{ x: 860 }}
            columns={[
              { title: columnLabel("name", t), dataIndex: "name", key: "name", width: 180 },
              {
                title: columnLabel("description", t),
                dataIndex: "description",
                key: "description",
                width: 260,
                render: (value: string | null) => value || t("roles.emptyDescription"),
              },
              {
                title: t("roles.userCount"),
                dataIndex: "user_count",
                key: "user_count",
                width: 132,
                render: (value: number) => <Tag>{value || 0}</Tag>,
              },
              {
                title: columnLabel("status", t),
                dataIndex: "status",
                key: "status",
                width: 120,
                render: (value: string) => <Tag>{optionLabel(value, t)}</Tag>,
              },
              {
                title: columnLabel("actions", t),
                key: "actions",
                width: 132,
                render: (_, row) => (
                  <Space size={6} wrap>
                    <CompactActionButton
                      title={t("roles.linkedUsers")}
                      icon={<LinkOutlined />}
                      onClick={() => void openLinkedUsers(row)}
                    />
                    <IconAction title={t("common.edit")} icon={<EditOutlined />} onClick={() => openEdit(row)} />
                    <Popconfirm
                      title={t("common.deleteConfirm", { title: row.name || t("roles.directory") })}
                      onConfirm={() => void deleteRole(String(row.id))}
                      {...popconfirmButtonProps(t, "delete")}
                    >
                      <Button size="small" icon={<DeleteOutlined />} />
                    </Popconfirm>
                  </Space>
                ),
              },
            ]}
          />
        )}
      </section>

      <Drawer
        title={editingRole ? t("common.editTitle", { title: t("nav.roles") }) : t("common.createTitle", { title: t("nav.roles") })}
        open={editorOpen}
        width={420}
        onClose={() => {
          setEditorOpen(false);
          setEditingRole(null);
        }}
        extra={<Button type="primary" onClick={() => void saveRole()}>{t("common.save")}</Button>}
      >
        <Form form={form} layout="vertical" initialValues={{ status: "active" }}>
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label={t("field.description")}>
            <Input.TextArea autoSize={{ minRows: 4, maxRows: 8 }} />
          </Form.Item>
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={t("roles.linkedUsersTitle", { name: String(linkedUsersRole?.name || "") })}
        open={Boolean(linkedUsersRole)}
        footer={null}
        onCancel={() => {
          setLinkedUsersRole(null);
          setLinkedUsers([]);
        }}
        width={760}
      >
        <Table
          size="small"
          rowKey={(row) => row.id || row.user_id || row.external_ref}
          loading={linkedUsersLoading}
          dataSource={linkedUsers}
          pagination={false}
          columns={[
            { title: columnLabel("name", t), dataIndex: "name", key: "name" },
            { title: columnLabel("external_ref", t), dataIndex: "external_ref", key: "external_ref" },
            { title: columnLabel("org_path", t), dataIndex: "org_path", key: "org_path" },
            {
              title: columnLabel("role_names", t),
              dataIndex: "role_names",
              key: "role_names",
              render: (value: string[]) => (
                <Space size={[6, 6]} wrap>
                  {(value || []).map((role) => <Tag key={role}>{role}</Tag>)}
                </Space>
              ),
            },
          ]}
        />
      </Modal>
    </section>
  );
}

function ImportPlatformPanel({
  platform,
  form,
  t,
}: {
  platform: ImportPlatformKey;
  form: FormInstance<AnyRecord>;
  t: (key: TranslationKey, params?: TranslationParams) => string;
}) {
  const config = buildImportPlatformUiConfig(platform, t);

  return (
    <div className="directory-import-uploader">
      <Typography.Text strong>{t("users.importPlatform")}</Typography.Text>
      <Typography.Paragraph>{t("users.importPlatformHint")}</Typography.Paragraph>
      <Form form={form} layout="vertical" initialValues={{ delimiter: "/" }}>
        <div className="platform-form-grid">
          {config.credentialFields.map((field) => (
            <Form.Item
              key={field.name}
              name={field.name}
              label={field.label}
            >
              {field.secret ? <Input.Password autoComplete="new-password" /> : <Input autoComplete="off" />}
            </Form.Item>
          ))}
          {config.extraFields.map((field) => (
            <Form.Item
              key={field.name}
              name={field.name}
              label={field.label}
            >
              <Input
                aria-label={field.label}
                autoComplete="off"
                placeholder={field.hint}
              />
            </Form.Item>
          ))}
        </div>
      </Form>
      <Collapse
        ghost
        className="directory-import-guide"
        items={[
          {
            key: `${platform}-guide`,
            label: t("users.platformGuide"),
            children: (
              <div className="directory-guide-copy">
                <ol>
                  {config.stepKeys.map((key) => (
                    <li key={key}>{t(key)}</li>
                  ))}
                </ol>
                <Typography.Text strong>{t("users.platformGuidePermissions")}</Typography.Text>
                <Typography.Paragraph>{t(config.permissionsKey)}</Typography.Paragraph>
                {platform === "feishu" ? (
                  <>
                    <Typography.Text strong>{t("users.platformGuideManifest")}</Typography.Text>
                    <pre className="directory-guide-snippet">
{`{
  "scopes": {
    "tenant": [
      "contact:contact.base:readonly",
      "contact:department.base:readonly",
      "contact:user.base:readonly",
      "contact:user.employee_id:readonly"
    ],
    "user": []
  }
}`}
                    </pre>
                    <Typography.Paragraph type="secondary">
                      {t("users.platformGuideManifestNote")}
                    </Typography.Paragraph>
                  </>
                ) : null}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
}

function buildImportPlatformUiConfig(
  platform: ImportPlatformKey,
  t: (key: TranslationKey, params?: TranslationParams) => string,
) {
  if (platform === "feishu") {
    return {
      credentialFields: [
        { name: "feishuAppId", label: t("users.platformAppId") },
        { name: "feishuAppSecret", label: t("users.platformAppSecret"), secret: true },
      ],
      extraFields: [
        {
          name: "feishuRootDepartmentId",
          label: t("users.platformRootDepartmentId"),
          hint: t("users.platformRootDepartmentHint"),
        },
      ],
      stepKeys: [
        "users.platformFeishuStep1",
        "users.platformFeishuStep2",
        "users.platformFeishuStep3",
        "users.platformFeishuStep4",
      ] as TranslationKey[],
      permissionsKey: "users.platformFeishuPermissions" as TranslationKey,
    };
  }

  if (platform === "wecom") {
    return {
      credentialFields: [
        { name: "wecomCorpId", label: t("users.platformCorpId") },
        { name: "wecomCorpSecret", label: t("users.platformCorpSecret"), secret: true },
      ],
      extraFields: [
        {
          name: "wecomRootDepartmentId",
          label: t("users.platformRootDepartmentId"),
          hint: t("users.platformRootDepartmentHint"),
        },
      ],
      stepKeys: [
        "users.platformWecomStep1",
        "users.platformWecomStep2",
        "users.platformWecomStep3",
      ] as TranslationKey[],
      permissionsKey: "users.platformWecomPermissions" as TranslationKey,
    };
  }

  return {
    credentialFields: [
      { name: "dingtalkAppKey", label: t("users.platformAppKey") },
      { name: "dingtalkAppSecret", label: t("users.platformAppSecret"), secret: true },
    ],
    extraFields: [
      {
        name: "dingtalkRootDepartmentId",
        label: t("users.platformRootDepartmentId"),
        hint: t("users.platformRootDepartmentHint"),
      },
    ],
    stepKeys: [
      "users.platformDingtalkStep1",
      "users.platformDingtalkStep2",
      "users.platformDingtalkStep3",
    ] as TranslationKey[],
    permissionsKey: "users.platformDingtalkPermissions" as TranslationKey,
  };
}

function EndpointTable({ api, title, path }: { api: ReturnType<typeof useApi>; title: TranslationKey; path: string }) {
  /** Render read-only endpoint data with row details in a drawer. */

  const { t } = useI18n();
  const state = useData<AnyRecord[]>(() => (path === "__empty__" ? Promise.resolve([]) : api.request(path)), [api.apiKey, path]);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const titleText = t(title);
  const columns = columnsFromRows(state.data || [], t);
  return (
    <>
      <DataPanel
        title={titleText}
        state={state}
        columns={columns}
        actions={(row) => <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />}
      />
      <RecordDetails record={selected} title={titleText} onClose={() => setSelected(null)} />
    </>
  );
}

function Datasources({
  api,
  jumpTarget,
  onJumpHandled,
}: {
  api: ReturnType<typeof useApi>;
  jumpTarget: CatalogJumpTarget | null;
  onJumpHandled: () => void;
}) {
  /** Unified datasource and asset catalog workspace. */

  const { t } = useI18n();
  const datasources = useData<AnyRecord[]>(() => api.request("/admin/datasources"), [api.apiKey]);
  const resources = useData<CatalogTreeNode[]>((page) => api.request(paginatedPath("/admin/resource-tree", page)), [api.apiKey], { paginated: true });
  const tags = useData<AnyRecord[]>(() => api.request("/admin/tags"), [api.apiKey]);
  const [search, setSearch] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const sourceTree = buildDatasourceTree(datasources.data || [], resources.data || []);
  const treeData = filterCatalogTree(sourceTree, search);
  const flatNodes = flattenCatalogTree(sourceTree);
  const visibleKeys = flattenCatalogTree(treeData).map((node) => node.key);
  const selected = flatNodes.find((node) => node.key === selectedKey) || null;
  const loading = datasources.loading || resources.loading || tags.loading;
  const error = datasources.error || resources.error || tags.error;
  const reloadAll = () => {
    datasources.reload();
    resources.reload();
    tags.reload();
  };

  useEffect(() => {
    if (!jumpTarget || loading || !datasources.data || !resources.data || !tags.data) {
      return;
    }
    const path = findTreePathByKey(sourceTree, jumpTarget.key);
    if (path.length) {
      setSearch("");
      setSelectedKey(jumpTarget.key);
      setExpandedKeys((current) => Array.from(new Set([...current, ...path.slice(0, -1)])));
    }
    onJumpHandled();
  }, [jumpTarget, loading, sourceTree, onJumpHandled]);

  return (
    <section className="resource-catalog">
      <div className="catalog-tree panel">
        <div className="panel-head">
          <Typography.Title level={4}>{t("catalog.treeTitle")}</Typography.Title>
          <Space>
            <Button icon={<PlusOutlined />} type="primary" onClick={() => setCreateOpen(true)}>
              {t("datasource.new")}
            </Button>
            <Button onClick={reloadAll}>{t("common.refresh")}</Button>
          </Space>
        </div>
        <div className="catalog-tree-body">
          <Input.Search
            allowClear
            className="catalog-search"
            placeholder={t("catalog.search")}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {error ? <Alert type="error" message={error} /> : null}
          <Tree
            blockNode
            className={loading ? "catalog-tree-loading" : undefined}
            showLine
            treeData={toAntTreeData(treeData, t)}
            selectedKeys={selectedKey ? [selectedKey] : []}
            expandedKeys={search ? visibleKeys : expandedKeys}
            onExpand={(keys) => setExpandedKeys(keys)}
            onSelect={(keys) => setSelectedKey(String(keys[0] || ""))}
          />
          {resources.pagination ? (
            <Pagination
              size="small"
              current={Math.floor(resources.pagination.offset / resources.pagination.limit) + 1}
              pageSize={resources.pagination.limit}
              total={resources.pagination.total}
              showSizeChanger
              onChange={(pageNumber, pageSize) => {
                setSelectedKey(null);
                resources.pagination?.setPage(pageSize, (pageNumber - 1) * pageSize);
              }}
            />
          ) : null}
        </div>
      </div>
      {selected ? (
        <CatalogDetail
          api={api}
          tags={tags.data || []}
          selected={selected}
          onSaved={reloadAll}
          onDeleted={() => {
            setSelectedKey(null);
            reloadAll();
          }}
        />
      ) : (
        <div className="catalog-detail panel">
          <div className="panel-head">
            <Typography.Title level={4}>{t("catalog.detailsTitle")}</Typography.Title>
            <Button type="primary" disabled>{t("common.save")}</Button>
          </div>
          <Empty className="catalog-empty" description={t("catalog.selectPrompt")} />
        </div>
      )}
      <DatasourceCreateDrawer
        api={api}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={reloadAll}
      />
    </section>
  );
}

function CatalogDetail({
  api,
  tags,
  selected,
  onSaved,
  onDeleted
}: {
  api: ReturnType<typeof useApi>;
  tags: AnyRecord[];
  selected: CatalogTreeNode;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  /** Route the selected catalog node to the correct detail editor. */

  if (selected.type === "datasource") {
    return (
      <DatasourceDetail
        api={api}
        tags={tags}
        selected={selected}
        onSaved={onSaved}
        onDeleted={onDeleted}
      />
    );
  }
  return <AssetDetail api={api} tags={tags} selected={selected} onSaved={onSaved} />;
}

function DatasourceConnectionFields({ passwordConfigured = false }: { passwordConfigured?: boolean }) {
  /** Render explicit relational connection inputs instead of raw JSON config. */

  const { t } = useI18n();
  const passwordPlaceholder = passwordConfigured
    ? SECRET_PLACEHOLDER_BULLETS
    : t("datasource.passwordPlaceholder");
  return (
    <>
      <div className="config-form-grid">
        <Form.Item
          name="host"
          label={t("field.host")}
          rules={[{ required: true, message: t("common.required", { label: t("field.host") }) }]}
        >
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item
          name="port"
          label={t("field.port")}
          rules={[{ required: true, message: t("common.required", { label: t("field.port") }) }]}
        >
          <InputNumber className="full" min={1} max={65535} />
        </Form.Item>
        <Form.Item
          name="database"
          label={t("field.database")}
          className="span-2"
        >
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item name="username" label={t("field.username")}>
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item name="password" label={t("field.password")}>
          <Input.Password autoComplete="new-password" placeholder={passwordPlaceholder} />
        </Form.Item>
      </div>
    </>
  );
}

function MaskingConfigFields({ form }: { form: FormInstance<AnyRecord> }) {
  /** Render strategy-specific masking controls and hide irrelevant config fields. */

  const { t } = useI18n();
  const strategy = String(Form.useWatch("strategy", form) || "fixed");

  if (strategy === "partial") {
    return (
      <>
        <Alert type="info" showIcon message={t("masking.partialHint")} />
        <div className="config-form-grid">
          <Form.Item
            name="prefix"
            label={t("field.prefix")}
            rules={[{ required: true, message: t("common.required", { label: t("field.prefix") }) }]}
          >
            <InputNumber className="full" min={0} />
          </Form.Item>
          <Form.Item
            name="suffix"
            label={t("field.suffix")}
            rules={[{ required: true, message: t("common.required", { label: t("field.suffix") }) }]}
          >
            <InputNumber className="full" min={0} />
          </Form.Item>
          <Form.Item
            name="fill"
            label={t("field.fill")}
            rules={[{ required: true, message: t("common.required", { label: t("field.fill") }) }]}
            className="span-2"
          >
            <Input autoComplete="off" maxLength={1} />
          </Form.Item>
        </div>
      </>
    );
  }

  if (strategy === "fixed") {
    return (
      <>
        <Alert type="info" showIcon message={t("masking.fixedHint")} />
        <Form.Item
          name="replacement"
          label={t("field.replacement")}
          rules={[{ required: true, message: t("common.required", { label: t("field.replacement") }) }]}
        >
          <Input autoComplete="off" />
        </Form.Item>
      </>
    );
  }

  return <Alert type="info" showIcon message={t("masking.noConfig")} />;
}

function DatasourceDetail({
  api,
  tags,
  selected,
  onSaved,
  onDeleted
}: {
  api: ReturnType<typeof useApi>;
  tags: AnyRecord[];
  selected: CatalogTreeNode;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  /** Editable datasource form embedded in the catalog detail pane. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [runningAction, setRunningAction] = useState<"test" | "scan" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    form.setFieldsValue(toDatasourceFormValues(selected));
    setActionError(null);
  }, [form, selected]);

  const showActionError = (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    setActionError(message);
    messageApi.error(message);
  };

  const save = async () => {
    const values = await form.validateFields();
    await api.request(`/admin/datasources/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify(normalizeDatasourceValues(values))
    });
    messageApi.success(t("common.saved"));
    onSaved();
  };
  const test = async () => {
    setRunningAction("test");
    setActionError(null);
    try {
      await api.request(`/admin/datasources/${selected.id}/test`, { method: "POST" });
      messageApi.success(t("datasource.tested"));
    } catch (error) {
      showActionError(error);
    } finally {
      setRunningAction(null);
    }
  };
  const scan = async () => {
    setRunningAction("scan");
    setActionError(null);
    try {
      await api.request(`/admin/datasources/${selected.id}/scan`, { method: "POST" });
      messageApi.success(t("datasource.scanned"));
      onSaved();
    } catch (error) {
      showActionError(error);
    } finally {
      setRunningAction(null);
    }
  };
  const remove = async () => {
    await api.request(`/admin/datasources/${selected.id}`, { method: "DELETE" });
    messageApi.success(t("common.deleted"));
    onDeleted();
  };

  return (
    <div className="catalog-detail panel">
      <div className="panel-head">
        <Typography.Title level={4}>{t("catalog.detailsTitle")}</Typography.Title>
        <Space>
          <Tag>{optionLabel(String(selected.status || "active"), t)}</Tag>
          <Button
            icon={<ExperimentOutlined />}
            loading={runningAction === "test"}
            disabled={Boolean(runningAction)}
            onClick={test}
          >
            {t("datasource.test")}
          </Button>
          <Button
            icon={<SyncOutlined />}
            loading={runningAction === "scan"}
            disabled={Boolean(runningAction)}
            onClick={scan}
          >
            {t("datasource.scan")}
          </Button>
          <Popconfirm
            title={t("datasource.deleteConfirm")}
            onConfirm={remove}
            {...popconfirmButtonProps(t, "delete")}
          >
            <Button icon={<DeleteOutlined />} />
          </Popconfirm>
          <Button type="primary" onClick={save}>{t("common.save")}</Button>
        </Space>
      </div>
      <div className="catalog-detail-body">
        <Descriptions bordered column={1} size="small">
          <Descriptions.Item label={t("catalog.nodeType")}>
            {t("nav.datasources")}
          </Descriptions.Item>
          <Descriptions.Item label={t("field.type")}>
            {optionLabel(String(selected.datasource_type || selected.type_name || selected.type), t)}
          </Descriptions.Item>
          <Descriptions.Item label={t("column.datasource_kind")}>
            {String(selected.datasource_kind || "")}
          </Descriptions.Item>
        </Descriptions>
        {actionError ? <Alert type="error" showIcon message={actionError} /> : null}
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
          <Form.Item name="description" label={t("field.description")}>
            <Input.TextArea autoComplete="off" autoSize={{ minRows: 4, maxRows: 10 }} />
          </Form.Item>
          <DatasourceConnectionFields passwordConfigured={datasourceHasConfiguredPassword(selected.config || {})} />
        </Form>
        <CatalogTagEditor
          api={api}
          targetType="datasource"
          targetId={selected.id}
          assignedTags={selected.tags || []}
          allTags={tags}
          onChanged={onSaved}
        />
      </div>
    </div>
  );
}

function AssetDetail({
  api,
  tags,
  selected,
  onSaved
}: {
  api: ReturnType<typeof useApi>;
  tags: AnyRecord[];
  selected: CatalogTreeNode;
  onSaved: () => void;
}) {
  /** Editable detail pane for database, table, and field catalog nodes. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const [form] = Form.useForm();
  const statusValue = Form.useWatch("status", form) || selected.status || "active";

  useEffect(() => {
    form.setFieldsValue(toCatalogFormValues(selected));
  }, [form, selected]);

  const save = async () => {
    const values = await form.validateFields();
    const endpoint =
      selected.type === "field"
        ? `/admin/resource-fields/${selected.id}`
        : `/admin/resources/${selected.id}`;
    await api.request(endpoint, {
      method: "PATCH",
      body: JSON.stringify(values)
    });
    messageApi.success(t("common.saved"));
    onSaved();
  };

  return (
    <div className="catalog-detail panel">
      <div className="panel-head">
        <Typography.Title level={4}>{t("catalog.detailsTitle")}</Typography.Title>
        <Space>
          <Tag>{optionLabel(String(selected.status || "active"), t)}</Tag>
          <Button type="primary" onClick={save}>{t("common.save")}</Button>
        </Space>
      </div>
      <div className="catalog-detail-body">
        <Descriptions bordered column={1} size="small">
          <Descriptions.Item label={t("catalog.nodeType")}>
            {selected.type === "field" ? t("tab.field") : optionLabel(String(selected.kind), t)}
          </Descriptions.Item>
          <Descriptions.Item label={t("column.path")}>
            <Typography.Text copyable>{String(selected.path || selected.name)}</Typography.Text>
          </Descriptions.Item>
          {selected.type === "field" ? (
            <Descriptions.Item label={t("catalog.fieldInfo")}>
              {selected.data_type} · {t("column.ordinal_position")} {selected.ordinal_position}
            </Descriptions.Item>
          ) : null}
        </Descriptions>
        <Form form={form} layout="vertical">
          {selected.type === "resource" ? (
            <>
              <Form.Item name="display_name" label={t("field.displayName")}>
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="query_language" label={t("field.queryLanguage")}>
                <Input autoComplete="off" />
              </Form.Item>
            </>
          ) : null}
          <Form.Item name="description" label={t("field.description")}>
            <Input.TextArea autoComplete="off" autoSize={{ minRows: 6, maxRows: 14 }} />
          </Form.Item>
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
          {statusValue === "disabled" ? (
            <Alert className="catalog-status-hint" type="info" showIcon message={t("catalog.disabledHint")} />
          ) : null}
        </Form>
        {selected.type === "resource" ? (
          <CatalogTagEditor
            api={api}
            targetType="resource"
            targetId={selected.id}
            assignedTags={selected.tags || []}
            allTags={tags}
            onChanged={onSaved}
          />
        ) : null}
      </div>
    </div>
  );
}

function CatalogTagEditor({
  api,
  targetType,
  targetId,
  assignedTags,
  allTags,
  onChanged
}: {
  api: ReturnType<typeof useApi>;
  targetType: "datasource" | "resource";
  targetId: string;
  assignedTags: AnyRecord[];
  allTags: AnyRecord[];
  onChanged: () => void;
}) {
  /** Manage tag bindings for datasource and resource detail panes. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const assignedIds = new Set(assignedTags.map((tag) => String(tag.id)));
  const options = allTags
    .filter((tag) => !assignedIds.has(String(tag.id)))
    .map((tag) => ({
      value: String(tag.id),
      label: `${String(tag.name)}${tag.category ? ` · ${String(tag.category)}` : ""}`,
      searchText: `${String(tag.name)} ${String(tag.category || "")} ${String(tag.description || "")}`.toLowerCase()
    }));

  const bindTag = async (tagId: string) => {
    await api.request(targetType === "datasource" ? "/admin/datasource-tags" : "/admin/resource-tags", {
      method: "POST",
      body: JSON.stringify(
        targetType === "datasource"
          ? { tag_id: tagId, datasource_id: targetId }
          : { tag_id: tagId, resource_id: targetId }
      )
    });
    messageApi.success(t("common.saved"));
    onChanged();
  };

  const unbindTag = async (tagId: string) => {
    const search = new URLSearchParams(
      targetType === "datasource"
        ? { tag_id: tagId, datasource_id: targetId }
        : { tag_id: tagId, resource_id: targetId }
    );
    await api.request(`/admin/${targetType}-tags?${search.toString()}`, {
      method: "DELETE"
    });
    messageApi.success(t("common.saved"));
    onChanged();
  };

  return (
    <div className="catalog-tag-editor">
      <Space direction="vertical" size={10} className="full">
        <Typography.Text strong>{t("catalog.tags")}</Typography.Text>
        <Select
          key={`${targetType}:${targetId}:${assignedTags.map((tag) => String(tag.id)).join(",")}`}
          showSearch
          allowClear
          className="catalog-tag-select"
          placeholder={t("placeholder.tagSearch")}
          options={options}
          onSelect={(value) => {
            void bindTag(String(value));
          }}
          filterOption={(input, option) =>
            String((option as { searchText?: string } | undefined)?.searchText || "")
              .includes(input.toLowerCase())
          }
        />
        {assignedTags.length ? (
          <Space wrap size={[8, 8]}>
            {assignedTags.map((tag) => (
              <Tag
                key={String(tag.id)}
                closable
                onClose={(event) => {
                  event.preventDefault();
                  void unbindTag(String(tag.id));
                }}
              >
                {String(tag.name)}
              </Tag>
            ))}
          </Space>
        ) : (
          <Typography.Text type="secondary">{t("catalog.noTags")}</Typography.Text>
        )}
      </Space>
    </div>
  );
}

function DatasourceCreateDrawer({
  api,
  open,
  onClose,
  onCreated
}: {
  api: ReturnType<typeof useApi>;
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  /** Drawer for creating a datasource without leaving the catalog workspace. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const [form] = Form.useForm();
  const create = async () => {
    const values = await form.validateFields();
    await api.request("/admin/datasources", {
      method: "POST",
      body: JSON.stringify(normalizeDatasourceValues(values))
    });
    messageApi.success(t("common.saved"));
    onClose();
    onCreated();
  };

  return (
    <Drawer
      title={t("common.createTitle", { title: t("nav.datasources") })}
      open={open}
      onClose={onClose}
      extra={<Button type="primary" onClick={create}>{t("common.save")}</Button>}
      width={520}
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{
          type: "postgres",
          status: "active",
          ...datasourceFormValuesFromConfig({})
        }}
      >
        <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}>
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item name="type" label={t("field.type")} rules={[{ required: true }]}>
          <Select options={["postgres", "mysql", "doris"].map((value) => ({ value, label: optionLabel(value, t) }))} />
        </Form.Item>
        <Form.Item name="status" label={t("field.status")} rules={[{ required: true }]}>
          <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
        </Form.Item>
        <Form.Item name="description" label={t("field.description")}>
          <Input.TextArea autoComplete="off" autoSize={{ minRows: 4, maxRows: 10 }} />
        </Form.Item>
        <DatasourceConnectionFields />
      </Form>
    </Drawer>
  );
}

function buildDatasourceTree(
  datasources: AnyRecord[],
  resourceRoots: CatalogTreeNode[],
): CatalogTreeNode[] {
  /** Attach scanned assets under their owning datasource root node. */

  return datasources.map((datasource) => ({
    key: `datasource:${datasource.id}`,
    type: "datasource",
    id: datasource.id,
    name: datasource.name,
    display_name: datasource.name,
    datasource_type: datasource.type,
    type_name: datasource.type,
    datasource_kind: datasource.datasource_kind,
    description: datasource.description,
    config: datasource.config,
    status: datasource.status,
    tags: datasource.tags || [],
    children: resourceRoots.filter((resource) => resource.datasource_id === datasource.id),
  }));
}

function flattenCatalogTree(nodes: CatalogTreeNode[]): CatalogTreeNode[] {
  /** Flatten the catalog tree for selection lookup and expansion control. */

  return nodes.flatMap((node) => [node, ...flattenCatalogTree(node.children || [])]);
}

function filterCatalogTree(nodes: CatalogTreeNode[], search: string): CatalogTreeNode[] {
  /** Keep matching nodes and ancestors so search still preserves hierarchy. */

  const needle = search.trim().toLowerCase();
  if (!needle) return nodes;
  const filtered: CatalogTreeNode[] = [];
  for (const node of nodes) {
    const children = filterCatalogTree(node.children || [], search);
    const haystack = [
      node.name,
      node.display_name,
      node.path,
      node.kind,
      node.data_type,
      node.description,
      node.datasource_type,
      (node.tags || []).map((tag: AnyRecord) => `${String(tag.name)} ${String(tag.category || "")}`).join(" "),
      JSON.stringify(node.config || {})
    ].join(" ").toLowerCase();
    if (haystack.includes(needle) || children.length) {
      filtered.push({ ...node, children });
    }
  }
  return filtered;
}

function toCatalogFormValues(node: CatalogTreeNode) {
  /** Extract only editable catalog fields from the selected tree node. */

  return node.type === "field"
    ? { description: node.description, status: node.status || "active" }
    : {
        display_name: node.display_name,
        description: node.description,
        query_language: node.query_language,
        status: node.status || "active"
      };
}

function toDatasourceFormValues(node: CatalogTreeNode) {
  /** Convert datasource nodes into form values with explicit connection fields. */

  return {
    name: node.name,
    status: node.status || "active",
    description: node.description,
    ...datasourceFormValuesFromConfig(node.config || {}),
  };
}

function normalizeDatasourceValues(values: AnyRecord) {
  /** Convert explicit datasource form fields into the admin API payload. */

  const { host, port, database, username, password, ...rest } = values;

  return {
    ...rest,
    config: datasourceConfigFromFormValues({ host, port, database, username, password }),
  };
}

function toMaskingFormValues(values: AnyRecord) {
  /** Expand masking policy config into dedicated form fields for the active strategy. */

  const strategy = String(values.strategy || "fixed");
  return {
    ...values,
    ...maskingFormValuesFromConfig(strategy, values.config || {}),
  };
}

function normalizeMaskingValues(values: AnyRecord) {
  /** Collapse strategy-specific masking controls back into the API payload shape. */

  const { replacement, prefix, suffix, fill, ...rest } = values;
  const strategy = String(rest.strategy || "fixed");
  return {
    ...rest,
    config: maskingConfigFromFormValues(strategy, { replacement, prefix, suffix, fill }),
  };
}

function applyMaskingStrategyDefaults(form: FormInstance<AnyRecord>, strategy: string) {
  /** Reset strategy-specific form fields so newly selected modes start with sane defaults. */

  form.setFieldsValue({
    replacement: undefined,
    prefix: undefined,
    suffix: undefined,
    fill: undefined,
    ...maskingFormValuesFromConfig(strategy, {}),
  });
}

function toAntTreeData(nodes: CatalogTreeNode[], t: I18nContextValue["t"]): AnyRecord[] {
  /** Convert API tree nodes into Ant Design tree data with status-aware labels. */

  return nodes.map((node) => {
    const children = toAntTreeData(node.children || [], t);
    const label = String(node.display_name || node.name);
    const meta = node.type === "datasource" ? String(node.datasource_type || "") : "";
    return {
      key: node.key,
      title: (
        <Space size={6} className="catalog-node-title">
          <span>{label}</span>
          {meta ? <Tag>{optionLabel(meta, t)}</Tag> : null}
          {node.status === "disabled" ? <Tag>{optionLabel("disabled", t)}</Tag> : null}
        </Space>
      ),
      ...(children.length ? { children } : {})
    };
  });
}

function toTagCatalogTreeData(
  nodes: CatalogTreeNode[],
  t: I18nContextValue["t"],
  onOpenNode: (node: CatalogTreeNode) => void,
): AnyRecord[] {
  /** Convert tag-linked catalog nodes into modal tree data with jump actions. */

  return nodes.map((node) => {
    const children = toTagCatalogTreeData(node.children || [], t, onOpenNode);
    const label = String(node.display_name || node.name);
    const meta = node.type === "datasource"
      ? String(node.datasource_type || "")
      : String(node.kind || "");
    return {
      key: node.key,
      title: (
        <div className="tag-catalog-node">
          <Space size={6} className="catalog-node-title">
            <span>{label}</span>
            {meta ? <Tag>{optionLabel(meta, t)}</Tag> : null}
            {node.status === "disabled" ? <Tag>{optionLabel("disabled", t)}</Tag> : null}
          </Space>
          <CompactActionButton
            title={t("catalog.jump")}
            icon={<RightCircleOutlined />}
            onClick={() => onOpenNode(node)}
          />
        </div>
      ),
      ...(children.length ? { children } : {}),
    };
  });
}

function Tags({
  api,
  onOpenCatalogNode,
}: {
  api: ReturnType<typeof useApi>;
  onOpenCatalogNode: (target: CatalogJumpTarget) => void;
}) {
  /** Governance tag CRUD page with reverse lookup into linked datasource assets. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const state = useData<AnyRecord[]>(() => api.request("/admin/tags"), [api.apiKey]);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [editing, setEditing] = useState<AnyRecord | null>(null);
  const [catalogTag, setCatalogTag] = useState<AnyRecord | null>(null);
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();

  const create = async () => {
    const values = await form.validateFields();
    await api.request("/admin/tags", {
      method: "POST",
      body: JSON.stringify(values)
    });
    messageApi.success(t("common.saved"));
    setOpen(false);
    state.reload();
  };

  const update = async () => {
    if (!editing) return;
    const values = await editForm.validateFields();
    await api.request(`/admin/tags/${editing.id}`, {
      method: "PATCH",
      body: JSON.stringify(values)
    });
    messageApi.success(t("common.saved"));
    setEditing(null);
    state.reload();
  };

  const remove = async (row: AnyRecord) => {
    await api.request(`/admin/tags/${row.id}`, { method: "DELETE" });
    messageApi.success(t("common.deleted"));
    if (catalogTag?.id === row.id) {
      setCatalogTag(null);
    }
    state.reload();
  };

  return (
    <Space direction="vertical" size={12} className="full">
      <Button
        type="primary"
        onClick={() => {
          form.resetFields();
          setOpen(true);
        }}
      >
        {t("common.create")}
      </Button>
      <DataPanel
      title={t("nav.tags")}
      state={state}
      columns={columnsFromRows(state.data || [], t)}
        actionsColumnWidth={156}
        actions={(row) => (
          <Space size={4} onClick={(event) => event.stopPropagation()}>
            <CompactActionButton
              title={t("tag.relatedAssets")}
              icon={<LinkOutlined />}
              onClick={() => setCatalogTag(row)}
            />
            <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />
            <IconAction
              title={t("common.edit")}
              icon={<EditOutlined />}
              onClick={() => {
                setEditing(row);
                editForm.setFieldsValue(row);
              }}
            />
            <Popconfirm
              title={t("common.deleteConfirm", { title: t("nav.tags") })}
              onConfirm={() => remove(row)}
              {...popconfirmButtonProps(t, "delete")}
            >
              <Button size="small" icon={<DeleteOutlined />} />
            </Popconfirm>
          </Space>
        )}
      />
      <RecordDetails record={selected} title={t("nav.tags")} onClose={() => setSelected(null)} />
      <Drawer
        title={t("common.createTitle", { title: t("nav.tags") })}
        open={open}
        onClose={() => setOpen(false)}
        extra={<Button type="primary" onClick={create}>{t("common.save")}</Button>}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="category" label={t("field.category")}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="description" label={t("field.description")}><Input.TextArea autoComplete="off" autoSize={{ minRows: 3, maxRows: 8 }} /></Form.Item>
        </Form>
      </Drawer>
      <Drawer
        title={t("common.editTitle", { title: t("nav.tags") })}
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        extra={<Button type="primary" onClick={update}>{t("common.save")}</Button>}
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="category" label={t("field.category")}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="description" label={t("field.description")}><Input.TextArea autoComplete="off" autoSize={{ minRows: 3, maxRows: 8 }} /></Form.Item>
        </Form>
      </Drawer>
      <TagCatalogModal
        api={api}
        tag={catalogTag}
        onClose={() => setCatalogTag(null)}
        onOpenCatalogNode={onOpenCatalogNode}
      />
    </Space>
  );
}

function TagCatalogModal({
  api,
  tag,
  onClose,
  onOpenCatalogNode,
}: {
  api: ReturnType<typeof useApi>;
  tag: AnyRecord | null;
  onClose: () => void;
  onOpenCatalogNode: (target: CatalogJumpTarget) => void;
}) {
  /** Show all datasource and resource nodes that are linked to a selected tag. */

  const { t } = useI18n();
  const state = useData<CatalogTreeNode[]>(
    () => (tag ? api.request(`/admin/tags/${tag.id}/catalog`) : Promise.resolve([])),
    [api.apiKey, tag?.id]
  );
  const openNode = (node: CatalogTreeNode) => {
    onOpenCatalogNode({ key: node.key });
    onClose();
  };

  return (
    <Modal
      title={t("tag.relatedAssetsTitle", { name: String(tag?.name || "") })}
      open={Boolean(tag)}
      onCancel={onClose}
      footer={null}
      width={820}
    >
      {state.error ? <Alert type="error" message={state.error} /> : null}
      {!state.error && !state.loading && !state.data?.length ? (
        <Empty description={t("tag.noLinkedAssets")} />
      ) : (
        <Tree
          blockNode
          className="tag-catalog-tree"
          showLine
          defaultExpandAll
          treeData={toTagCatalogTreeData(state.data || [], t, openNode)}
        />
      )}
    </Modal>
  );
}

function Policies({ api }: { api: ReturnType<typeof useApi> }) {
  /** Policy area split into resource-level and field-level tabs. */

  const { t } = useI18n();
  return (
    <Tabs
      items={[
        { key: "resource", label: t("tab.resource"), children: <CrudPolicy api={api} kind="resource" /> },
        { key: "field", label: t("tab.field"), children: <CrudPolicy api={api} kind="field" /> }
      ]}
    />
  );
}

function CrudPolicy({ api, kind }: { api: ReturnType<typeof useApi>; kind: "resource" | "field" }) {
  /** Shared policy CRUD page that adapts required fields by policy kind. */

  const isField = kind === "field";
  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const datasources = useData<AnyRecord[]>(() => api.request("/admin/datasources"), [api.apiKey]);
  const resources = useData<AnyRecord[]>(() => loadAllPaginated<AnyRecord>(api.request, "/admin/resources"), [api.apiKey]);
  const tags = useData<AnyRecord[]>(() => api.request("/admin/tags"), [api.apiKey]);
  const users = useData<DirectoryUserRecord[]>(() => api.request("/admin/users"), [api.apiKey]);
  const roles = useData<AnyRecord[]>(() => api.request("/admin/roles"), [api.apiKey]);
  const state = useData<AnyRecord[]>(() => api.request(`/admin/${kind}-policies`), [api.apiKey, kind]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [editing, setEditing] = useState<AnyRecord | null>(null);
  const [targetMode, setTargetMode] = useState<PolicyTargetMode>("resource");
  const [editingTargetMode, setEditingTargetMode] = useState<PolicyTargetMode>("resource");
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();
  const createSubjectType = Form.useWatch("subject_type", form) || "user";
  const editSubjectType = Form.useWatch("subject_type", editForm) || "user";

  const openCreate = () => {
    setTargetMode("resource");
    form.resetFields();
    form.setFieldsValue({
      subject_type: "user",
      effect: "allow",
      action: "read",
      allow_decrypt: false,
      resource_scope_keys: [],
      status: "active",
    });
    setOpen(true);
  };

  const create = async () => {
    const values = await form.validateFields();
    const isBatchResourcePolicy = !isField && targetMode === "resource";
    await api.request(isBatchResourcePolicy ? "/admin/resource-policies/batch" : `/admin/${kind}-policies`, {
      method: "POST",
      body: JSON.stringify(normalizePolicyValues(values, targetMode, isField, { batch: isBatchResourcePolicy })),
    });
    messageApi.success(t("common.saved"));
    setOpen(false);
    state.reload();
  };

  const update = async () => {
    if (!editing) return;
    const values = await editForm.validateFields();
    if (!isField && isGroupedResourcePolicyRow(editing)) {
      await api.request(`/admin/${kind}-policies/${editing.id}`, {
        method: "PATCH",
        body: JSON.stringify(normalizePolicyValues(
          values,
          editingTargetMode,
          isField,
          { batch: true },
        )),
      });
      messageApi.success(t("common.saved"));
      setEditing(null);
      state.reload();
      return;
    }
    if (!isField && editingTargetMode === "resource") {
      const scopeKeys = normalizeResourceScopeKeys(values.resource_scope_keys);
      const [primaryScopeKey, ...extraScopeKeys] = scopeKeys;
      await api.request(`/admin/${kind}-policies/${editing.id}`, {
        method: "PATCH",
        body: JSON.stringify(normalizePolicyValues(
          { ...values, resource_scope_keys: primaryScopeKey ? [primaryScopeKey] : [] },
          editingTargetMode,
          isField,
        )),
      });
      if (extraScopeKeys.length > 0) {
        await api.request("/admin/resource-policies/batch", {
          method: "POST",
          body: JSON.stringify(normalizePolicyValues(
            { ...values, resource_scope_keys: extraScopeKeys },
            editingTargetMode,
            isField,
            { batch: true },
          )),
        });
      }
      messageApi.success(t("common.saved"));
      setEditing(null);
      state.reload();
      return;
    }
    await api.request(`/admin/${kind}-policies/${editing.id}`, {
      method: "PATCH",
      body: JSON.stringify(normalizePolicyValues(values, editingTargetMode, isField)),
    });
    messageApi.success(t("common.saved"));
    setEditing(null);
    state.reload();
  };

  const remove = async (row: AnyRecord) => {
    await api.request(`/admin/${kind}-policies/${row.id}`, { method: "DELETE" });
    messageApi.success(t("common.deleted"));
    state.reload();
  };

  const policyForm = (
    targetForm: FormInstance<AnyRecord>,
    currentSubjectType: string,
    currentTargetMode: PolicyTargetMode,
    setCurrentTargetMode: React.Dispatch<React.SetStateAction<PolicyTargetMode>>,
  ) => {
    const effectValue = Form.useWatch("effect", targetForm) || "allow";
    return (
      <Form form={targetForm} layout="vertical">
        <div className="config-form-grid">
          <Form.Item
            name="subject_type"
            label={t("field.subjectType")}
            rules={[{ required: true, message: t("common.required", { label: t("field.subjectType") }) }]}
          >
            <Select
              options={["all", "user", "role"].map((value) => ({ value, label: optionLabel(value, t) }))}
              onChange={(value) => {
                if (value === "all") {
                  targetForm.setFieldValue("subject_id", "all");
                } else if (targetForm.getFieldValue("subject_id") === "all") {
                  targetForm.setFieldValue("subject_id", undefined);
                }
              }}
            />
          </Form.Item>
          <Form.Item
            name="subject_id"
            label={t("field.subject")}
            rules={currentSubjectType === "all" ? undefined : [{ required: true, message: t("common.required", { label: t("field.subject") }) }]}
          >
            <PolicySubjectSelect
              subjectType={String(currentSubjectType)}
              users={users.data || []}
              roles={roles.data || []}
              t={t}
            />
          </Form.Item>
          <Form.Item
            name="effect"
            label={t("field.effect")}
            rules={[{ required: true, message: t("common.required", { label: t("field.effect") }) }]}
          >
            <Select options={["allow", "deny"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
          <Form.Item
            name="action"
            label={t("field.action")}
            rules={[{ required: true, message: t("common.required", { label: t("field.action") }) }]}
          >
            <Input autoComplete="off" />
          </Form.Item>
        </div>
        {!isField ? (
          <div className="config-form-grid">
            <Form.Item label={t("field.type")}>
              <Select
                value={currentTargetMode}
                options={[
                  { value: "resource", label: t("tab.resource") },
                  { value: "tag", label: t("tab.tag") },
                ]}
                onChange={(value) => {
                  setCurrentTargetMode(value);
                  targetForm.setFieldsValue({
                    resource_scope_keys: [],
                    tag_id: undefined,
                  });
                }}
              />
            </Form.Item>
            {currentTargetMode === "resource" ? (
              <Form.Item
                name="resource_scope_keys"
                label={t("field.resourceId")}
                className="span-2"
                rules={[{
                  validator: (_, value) =>
                    Array.isArray(value) && value.length > 0
                      ? Promise.resolve()
                      : Promise.reject(new Error(t("common.required", { label: t("field.resourceId") }))),
                }]}
              >
                <ResourceScopeTransfer
                  datasources={datasources.data || []}
                  resources={resources.data || []}
                  loading={datasources.loading || resources.loading}
                  t={t}
                />
              </Form.Item>
            ) : (
              <Form.Item
                name="tag_id"
                label={columnLabel("tag_id", t)}
                rules={[{ required: true, message: t("common.required", { label: columnLabel("tag_id", t) }) }]}
              >
                <TagSelect tags={tags.data || []} t={t} />
              </Form.Item>
            )}
            <Form.Item
              name="allow_decrypt"
              label={t("field.allowDecrypt")}
              valuePropName="checked"
            >
              <Switch disabled={effectValue !== "allow"} />
            </Form.Item>
          </div>
        ) : null}
        {isField ? (
          <div className="config-form-grid">
            <Form.Item
              name="resource_id"
              label={t("field.resourceId")}
              rules={[{ required: true, message: t("common.required", { label: t("field.resourceId") }) }]}
            >
              <ResourceSelect
                resources={resources.data || []}
                loading={resources.loading}
                selectableKinds={["relational_table", "relational_view"]}
                t={t}
              />
            </Form.Item>
            <Form.Item
              name="field_name"
              label={t("field.field")}
              rules={[{ required: true, message: t("common.required", { label: t("field.field") }) }]}
            >
              <Input autoComplete="off" />
            </Form.Item>
          </div>
        ) : null}
        <div className="config-form-grid">
          <Form.Item name="status" label={t("field.status")}>
            <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
          </Form.Item>
        </div>
      </Form>
    );
  };

  const resourcePolicyDetailItems = !isField && selected
    ? [{
        key: "resource_policy_scopes",
        label: columnLabel("scopes", t),
        children: (
          <ResourcePolicyScopeDetails
            policy={selected}
            datasources={datasources.data || []}
            resources={resources.data || []}
            tags={tags.data || []}
            t={t}
          />
        ),
      }]
    : undefined;
  const resourcePolicyDetailHiddenKeys = !isField
    ? [
        "datasource_id",
        "datasource_label",
        "datasource_count",
        "resource_id",
        "resource_label",
        "resource_count",
        "tag_id",
        "tag_name",
        "tag_count",
      ]
    : undefined;

  return (
    <Space direction="vertical" size={12} className="full">
      <Button type="primary" onClick={openCreate}>{t("common.create")}</Button>
      <DataPanel
        title={t(isField ? "policy.fieldPolicies" : "policy.resourcePolicies")}
        state={state}
        columns={[
          { title: columnLabel("subject_type", t), dataIndex: "subject_type", key: "subject_type", render: (value: string) => optionLabel(value, t) },
          { title: columnLabel("subject_id", t), dataIndex: "subject_label", key: "subject_label" },
          { title: columnLabel("effect", t), dataIndex: "effect", key: "effect", render: (value: string) => optionLabel(value, t) },
          { title: columnLabel("action", t), dataIndex: "action", key: "action" },
          ...(isField
            ? []
            : [{
                title: t("field.allowDecrypt"),
                dataIndex: "allow_decrypt",
                key: "allow_decrypt",
                render: (value: boolean) => (value ? t("common.yes") : t("common.no")),
              }]),
          ...(isField ? [] : [{
            title: columnLabel("datasource_label", t),
            dataIndex: "datasource_count",
            key: "datasource_count",
            render: (_value: unknown, row: AnyRecord) => resourcePolicyScopeCountText(row, "datasource_count", "datasource_ids", "datasource_id", t),
          }]),
          ...(isField ? [] : [{
            title: columnLabel("tag_name", t),
            dataIndex: "tag_count",
            key: "tag_count",
            render: (_value: unknown, row: AnyRecord) => resourcePolicyScopeCountText(row, "tag_count", "tag_ids", "tag_id", t),
          }]),
          ...(isField
            ? [{ title: columnLabel("resource_label", t), dataIndex: "resource_label", key: "resource_label" }]
            : [{
                title: columnLabel("resource_label", t),
                dataIndex: "resource_count",
                key: "resource_count",
                render: (_value: unknown, row: AnyRecord) => resourcePolicyScopeCountText(row, "resource_count", "resource_ids", "resource_id", t),
              }]),
          ...(isField ? [{ title: columnLabel("field_name", t), dataIndex: "field_name", key: "field_name" }] : []),
          { title: columnLabel("status", t), dataIndex: "status", key: "status", render: (value: string) => optionLabel(value, t) },
        ]}
        actions={(row) => (
          <Space size={4} onClick={(event) => event.stopPropagation()}>
            <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />
            <IconAction
              title={t("common.edit")}
              icon={<EditOutlined />}
              onClick={() => {
                setEditing(row);
                setEditingTargetMode(resourcePolicyTargetMode(row));
                editForm.setFieldsValue({
                  ...row,
                  tag_id: tagIdFromPolicy(row),
                  resource_scope_keys: resourceScopeKeysFromPolicy(row),
                });
              }}
            />
            <Popconfirm
              title={t("common.deleteConfirm", {
                title: t(isField ? "policy.fieldPolicies" : "policy.resourcePolicies"),
              })}
              onConfirm={() => remove(row)}
              {...popconfirmButtonProps(t, "delete")}
            >
              <Button size="small" icon={<DeleteOutlined />} />
            </Popconfirm>
          </Space>
        )}
      />
      <RecordDetails
        record={selected}
        title={t(isField ? "policy.fieldPolicies" : "policy.resourcePolicies")}
        onClose={() => setSelected(null)}
        extraItems={resourcePolicyDetailItems}
        hiddenKeys={resourcePolicyDetailHiddenKeys}
        width={isField ? undefined : 720}
      />
      <Drawer
        title={t("common.createTitle", { title: t(isField ? "policy.fieldPolicies" : "policy.resourcePolicies") })}
        open={open}
        width={isField ? undefined : 780}
        onClose={() => setOpen(false)}
        extra={<Button type="primary" onClick={() => void create()}>{t("common.save")}</Button>}
      >
        {policyForm(form, createSubjectType, targetMode, setTargetMode)}
      </Drawer>
      <Drawer
        title={t("common.editTitle", { title: t(isField ? "policy.fieldPolicies" : "policy.resourcePolicies") })}
        open={Boolean(editing)}
        width={isField ? undefined : 780}
        onClose={() => setEditing(null)}
        extra={<Button type="primary" onClick={() => void update()}>{t("common.save")}</Button>}
      >
        {policyForm(editForm, editSubjectType, editingTargetMode, setEditingTargetMode)}
      </Drawer>
    </Space>
  );
}

function Masking({ api }: { api: ReturnType<typeof useApi> }) {
  /** Masking policy CRUD page with strategy-aware config forms. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const resources = useData<AnyRecord[]>(() => loadAllPaginated<AnyRecord>(api.request, "/admin/resources"), [api.apiKey]);
  const state = useData<AnyRecord[]>(() => api.request("/admin/masking-policies"), [api.apiKey]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [editing, setEditing] = useState<AnyRecord | null>(null);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();

  const openCreate = () => {
    form.resetFields();
    form.setFieldsValue(toMaskingFormValues({ strategy: "fixed", status: "active", config: { replacement: "REDACTED" } }));
    setOpen(true);
  };

  const create = async () => {
    const values = await form.validateFields();
    await api.request("/admin/masking-policies", {
      method: "POST",
      body: JSON.stringify(normalizeMaskingValues(values))
    });
    messageApi.success(t("common.saved"));
    setOpen(false);
    state.reload();
  };

  const update = async () => {
    if (!editing) return;
    const values = await editForm.validateFields();
    await api.request(`/admin/masking-policies/${editing.id}`, {
      method: "PATCH",
      body: JSON.stringify(normalizeMaskingValues(values))
    });
    messageApi.success(t("common.saved"));
    setEditing(null);
    state.reload();
  };

  const remove = async (row: AnyRecord) => {
    await api.request(`/admin/masking-policies/${row.id}`, { method: "DELETE" });
    messageApi.success(t("common.deleted"));
    state.reload();
  };

  const maskingForm = (targetForm: FormInstance<AnyRecord>) => (
    <Form form={targetForm} layout="vertical">
      <Form.Item
        name="resource_id"
        label={t("field.resourceId")}
        rules={[{ required: true, message: t("common.required", { label: t("field.resourceId") }) }]}
      >
        <ResourceSelect
          resources={resources.data || []}
          loading={resources.loading}
          selectableKinds={["relational_table", "relational_view"]}
          t={t}
        />
      </Form.Item>
      <Form.Item
        name="field_name"
        label={t("field.field")}
        rules={[{ required: true, message: t("common.required", { label: t("field.field") }) }]}
      >
        <Input autoComplete="off" />
      </Form.Item>
      <div className="config-form-grid">
        <Form.Item name="subject_type" label={t("field.subjectType")}>
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item name="subject_id" label={t("field.subject")}>
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item
          name="strategy"
          label={t("field.strategy")}
          rules={[{ required: true, message: t("common.required", { label: t("field.strategy") }) }]}
        >
          <Select
            options={["fixed", "partial", "hash", "reversible"].map((value) => ({ value, label: optionLabel(value, t) }))}
            onChange={(value) => {
              applyMaskingStrategyDefaults(targetForm, String(value));
            }}
          />
        </Form.Item>
        <Form.Item name="status" label={t("field.status")}>
          <Select options={["active", "disabled"].map((value) => ({ value, label: optionLabel(value, t) }))} />
        </Form.Item>
      </div>
      <MaskingConfigFields form={targetForm} />
    </Form>
  );

  return (
    <Space direction="vertical" size={12} className="full">
      <Button type="primary" onClick={openCreate}>{t("common.create")}</Button>
      <DataPanel
        title={t("nav.masking")}
        state={state}
        columns={columnsFromRows(state.data || [], t)}
        actions={(row) => (
          <Space size={4} onClick={(event) => event.stopPropagation()}>
            <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />
            <IconAction
              title={t("common.edit")}
              icon={<EditOutlined />}
              onClick={() => {
                setEditing(row);
                editForm.setFieldsValue(toMaskingFormValues(row));
              }}
            />
            <Popconfirm
              title={t("common.deleteConfirm", { title: t("nav.masking") })}
              onConfirm={() => remove(row)}
              {...popconfirmButtonProps(t, "delete")}
            >
              <Button size="small" icon={<DeleteOutlined />} />
            </Popconfirm>
          </Space>
        )}
      />
      <RecordDetails record={selected} title={t("nav.masking")} onClose={() => setSelected(null)} />
      <Drawer
        title={t("common.createTitle", { title: t("nav.masking") })}
        open={open}
        onClose={() => setOpen(false)}
        extra={<Button type="primary" onClick={create}>{t("common.save")}</Button>}
      >
        {maskingForm(form)}
      </Drawer>
      <Drawer
        title={t("common.editTitle", { title: t("nav.masking") })}
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        extra={<Button type="primary" onClick={update}>{t("common.save")}</Button>}
      >
        {maskingForm(editForm)}
      </Drawer>
    </Space>
  );
}

function ApiKeys({ api }: { api: ReturnType<typeof useApi> }) {
  /** API key management page; raw keys are shown only after creation. */

  const { message: messageApi, modal } = AntApp.useApp();
  const { t } = useI18n();
  const serviceKeyScopeOptions = [
    { value: "admin", label: "admin" },
  ];
  const state = useData<AnyRecord[]>(() => api.request("/admin/api-keys"), [api.apiKey]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [editing, setEditing] = useState<AnyRecord | null>(null);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();
  const create = async () => {
    const values = await form.validateFields();
    const created = await api.request<AnyRecord>("/admin/api-keys", {
      method: "POST",
      body: JSON.stringify({ name: values.name, scopes: values.scopes })
    });
    modal.info({ title: t("apiKey.newTitle"), content: <Typography.Text copyable>{created.api_key}</Typography.Text> });
    setOpen(false);
    state.reload();
  };
  const edit = async () => {
    if (!editing) return;
    const values = await editForm.validateFields();
    await api.request(`/admin/api-keys/${editing.id}`, {
      method: "PATCH",
      body: JSON.stringify(values)
    });
    messageApi.success(t("common.saved"));
    setEditing(null);
    state.reload();
  };
  const revoke = async (row: AnyRecord) => {
    await api.request(`/admin/api-keys/${row.id}/revoke`, { method: "POST" });
    messageApi.success(t("common.revoked"));
    state.reload();
  };
  return (
    <Space direction="vertical" size={12} className="full">
      <Alert type="info" showIcon message={t("apiKey.serviceTitle")} description={t("apiKey.serviceDescription")} />
      <Button type="primary" onClick={() => setOpen(true)}>{t("apiKey.serviceCreate")}</Button>
      <DataPanel
        title={t("nav.apiKeys")}
        state={state}
        columns={columnsFromRows(state.data || [], t)}
        actions={(row) => (
          <Space size={4}>
            <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />
            <IconAction
              title={t("common.edit")}
              icon={<EditOutlined />}
              onClick={() => {
                setEditing(row);
                editForm.setFieldsValue(row);
              }}
            />
            <Popconfirm
              title={t("common.revokeConfirm")}
              onConfirm={() => revoke(row)}
              {...popconfirmButtonProps(t, "revoke")}
            >
              <Tooltip title={t("common.revoke")}>
                <Button size="small" aria-label={t("common.revoke")} icon={<StopOutlined />} />
              </Tooltip>
            </Popconfirm>
          </Space>
        )}
      />
      <RecordDetails record={selected} title={t("nav.apiKeys")} onClose={() => setSelected(null)} />
      <Drawer title={t("common.createTitle", { title: t("nav.apiKeys") })} open={open} onClose={() => setOpen(false)} extra={<Button type="primary" onClick={create}>{t("common.save")}</Button>}>
        <Form form={form} layout="vertical" initialValues={{ scopes: ["admin"] }}>
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="scopes" label={t("field.scopes")} rules={[{ required: true }]}>
            <Select mode="multiple" options={serviceKeyScopeOptions} />
          </Form.Item>
        </Form>
      </Drawer>
      <Drawer title={t("common.editTitle", { title: t("nav.apiKeys") })} open={Boolean(editing)} onClose={() => setEditing(null)} extra={<Button type="primary" onClick={edit}>{t("common.save")}</Button>}>
        <Form form={editForm} layout="vertical">
          <Form.Item name="name" label={t("field.name")} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="scopes" label={t("field.scopes")} rules={[{ required: true }]}>
            <Select mode="multiple" options={serviceKeyScopeOptions} />
          </Form.Item>
        </Form>
      </Drawer>
    </Space>
  );
}

function mcpPlatformTitleKey(platform: McpPlatformKey) {
  return `mcp.platform.${platform}.title` as TranslationKey;
}

function mcpPlatformSummaryKey(platform: McpPlatformKey) {
  return `mcp.platform.${platform}.summary` as TranslationKey;
}

function mcpPlatformSteps(platform: McpPlatformKey, t: I18nContextValue["t"]) {
  return [1, 2, 3].map((index) => t(`mcp.platform.${platform}.step${index}` as TranslationKey));
}

function mcpToolDescription(name: string, fallback: string, t: I18nContextValue["t"]) {
  const key = `mcp.tool.${name}` as TranslationKey;
  return key in translations["en-US"] ? t(key) : fallback;
}

function McpSetup({ api }: { api: ReturnType<typeof useApi> }) {
  /** Show standardized MCP connection details and client-specific import examples. */

  const { t } = useI18n();
  const state = useData<McpSetupPayload>(() => api.request("/admin/mcp/setup"), [api.apiKey]);
  if (state.error) return <Alert type="error" message={state.error} />;
  if (!state.data) return <Empty />;
  const guides = buildMcpPlatformGuides(state.data);
  const toolColumns: ColumnsType<McpSetupPayload["tools"][number]> = [
    {
      title: t("field.name"),
      dataIndex: "name",
      key: "name",
      render: (value: string) => <Tag>{value}</Tag>,
    },
    {
      title: t("column.description"),
      dataIndex: "description",
      key: "description",
      render: (value: string, row) => mcpToolDescription(row.name, value, t),
    },
  ];
  return (
    <Space direction="vertical" size={18} className="full">
      <section className="mcp-section">
        <div className="mcp-section-heading">
          <Typography.Title level={4}>{t("mcp.summaryTitle")}</Typography.Title>
          <Typography.Paragraph>{t("mcp.summaryDescription")}</Typography.Paragraph>
        </div>
        <Descriptions bordered column={1} size="small">
          <Descriptions.Item label={t("mcp.serverUrl")}>
            <Typography.Text copyable>{state.data.server_url}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("mcp.toolUrl")}>
            <Typography.Text copyable>{state.data.http_tool_url_template}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("mcp.transport")}>{t("mcp.transportValue")}</Descriptions.Item>
          <Descriptions.Item label={t("mcp.apiKeyHeader")}>
            <Typography.Text copyable>{state.data.api_key_header}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("mcp.authMode")}>
            {t("mcp.authModeValue", { header: state.data.api_key_header })}
          </Descriptions.Item>
        </Descriptions>
      </section>

      <section className="mcp-section">
        <div className="mcp-section-heading">
          <Typography.Title level={4}>{t("mcp.tools")}</Typography.Title>
        </div>
        <Table
          rowKey="name"
          size="small"
          pagination={false}
          columns={toolColumns}
          dataSource={state.data.tools}
        />
      </section>

      <section className="mcp-section">
        <div className="mcp-section-heading">
          <Typography.Title level={4}>{t("mcp.platformsTitle")}</Typography.Title>
          <Typography.Paragraph>{t("mcp.platformsDescription")}</Typography.Paragraph>
        </div>
        <Tabs
          className="mcp-platform-tabs"
          items={guides.map((guide) => ({
            key: guide.key,
            label: t(mcpPlatformTitleKey(guide.key)),
            children: (
              <div className="mcp-platform-panel">
                <Typography.Paragraph className="mcp-platform-summary">
                  {t(mcpPlatformSummaryKey(guide.key))}
                </Typography.Paragraph>
                <ol className="mcp-platform-steps">
                  {mcpPlatformSteps(guide.key, t).map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                <div className="mcp-snippet-list">
                  {guide.snippets.map((snippet) => (
                    <section key={`${guide.key}-${snippet.label}`} className="mcp-snippet">
                      <div className="mcp-snippet-header">
                        <Typography.Text strong>{snippet.label}</Typography.Text>
                        <Typography.Text copyable={{ text: snippet.code }}>
                          {snippet.language.toUpperCase()}
                        </Typography.Text>
                      </div>
                      <pre className="mcp-code-block"><code>{snippet.code}</code></pre>
                    </section>
                  ))}
                </div>
              </div>
            ),
          }))}
        />
      </section>

      <section className="mcp-section">
        <div className="mcp-section-heading">
          <Typography.Title level={4}>{t("mcp.notesTitle")}</Typography.Title>
        </div>
        <ul className="mcp-notes">
          <li>{t("mcp.note.runtimeKey")}</li>
          <li>{t("mcp.note.identity")}</li>
          <li>{t("mcp.note.reload")}</li>
        </ul>
      </section>
    </Space>
  );
}

function CrudPanel({
  api,
  title,
  listPath,
  createPath,
  updatePath,
  deletePath,
  fields,
  initialValues,
  onRow,
  stateOverride
}: {
  api: ReturnType<typeof useApi>;
  title: TranslationKey;
  listPath: string;
  createPath?: string;
  updatePath?: (row: AnyRecord) => string;
  deletePath?: (row: AnyRecord) => string;
  fields: FieldConfig[];
  initialValues: AnyRecord;
  onRow?: (row: AnyRecord) => React.HTMLAttributes<HTMLElement>;
  stateOverride?: { data: AnyRecord[] | null; loading: boolean; error: string | null; reload: () => void };
}) {
  /** Generic CRUD shell used by most console tables and drawer forms. */

  const { message: messageApi } = AntApp.useApp();
  const { t } = useI18n();
  const titleText = t(title);
  const loadedState = useData<AnyRecord[]>(() => api.request(listPath), [api.apiKey, listPath]);
  const state = stateOverride || loadedState;
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [editing, setEditing] = useState<AnyRecord | null>(null);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();
  const save = async () => {
    // Create payloads merge defaults with form values before JSON normalization.
    if (!createPath) return;
    const values = await form.validateFields();
    await api.request(createPath, {
      method: "POST",
      body: JSON.stringify(normalizeValues({ ...initialValues, ...values }, fields, t))
    });
    messageApi.success(t("common.saved"));
    setOpen(false);
    state.reload();
  };
  const update = async () => {
    // Update payloads include only the edit drawer values.
    if (!editing || !updatePath) return;
    const values = await editForm.validateFields();
    await api.request(updatePath(editing), {
      method: "PATCH",
      body: JSON.stringify(normalizeValues(values, fields, t))
    });
    messageApi.success(t("common.saved"));
    setEditing(null);
    state.reload();
  };
  const remove = async (row: AnyRecord) => {
    if (!deletePath) return;
    await api.request(deletePath(row), { method: "DELETE" });
    messageApi.success(t("common.deleted"));
    state.reload();
  };
  return (
    <Space direction="vertical" size={12} className="full">
      {createPath ? <Button type="primary" onClick={() => { form.resetFields(); form.setFieldsValue(toFormValues(initialValues, fields)); setOpen(true); }}>{t("common.create")}</Button> : null}
      <DataPanel
        title={titleText}
        state={state}
        columns={columnsFromRows(state.data || [], t)}
        onRow={onRow}
        actions={(row) => (
          <Space size={4} onClick={(event) => event.stopPropagation()}>
            <IconAction title={t("common.view")} icon={<EyeOutlined />} onClick={() => setSelected(row)} />
            {updatePath ? (
              <IconAction
                title={t("common.edit")}
                icon={<EditOutlined />}
                onClick={() => {
                  setEditing(row);
                  editForm.setFieldsValue(toFormValues(row, fields));
                }}
              />
            ) : null}
            {deletePath ? (
              <Popconfirm
                title={t("common.deleteConfirm", { title: titleText })}
                onConfirm={() => remove(row)}
                {...popconfirmButtonProps(t, "delete")}
              >
                <Button size="small" icon={<DeleteOutlined />} />
              </Popconfirm>
            ) : null}
          </Space>
        )}
      />
      <RecordDetails record={selected} title={titleText} onClose={() => setSelected(null)} />
      <Drawer title={t("common.createTitle", { title: titleText })} open={open} onClose={() => setOpen(false)} extra={<Button type="primary" onClick={save}>{t("common.save")}</Button>}>
        <Form form={form} layout="vertical" initialValues={toFormValues(initialValues, fields)}>
          {fields.map((field) => renderField(field, t))}
        </Form>
      </Drawer>
      <Drawer title={t("common.editTitle", { title: titleText })} open={Boolean(editing)} onClose={() => setEditing(null)} extra={<Button type="primary" onClick={update}>{t("common.save")}</Button>}>
        <Form form={editForm} layout="vertical">
          {fields.map((field) => renderField(field, t))}
        </Form>
      </Drawer>
    </Space>
  );
}

function DataPanel({
  title,
  state,
  columns,
  actions,
  onRow,
  actionsColumnWidth = 112,
}: {
  title: string;
  state: { data: AnyRecord[] | null; loading: boolean; error: string | null; reload: () => void; pagination?: PaginationState | null };
  columns: ColumnsType<AnyRecord>;
  actions?: (row: AnyRecord) => React.ReactNode;
  onRow?: (row: AnyRecord) => React.HTMLAttributes<HTMLElement>;
  actionsColumnWidth?: number;
}) {
  /** Shared table panel with optional row actions and a reload control. */

  const { t } = useI18n();
  const count = state.pagination?.total ?? state.data?.length ?? 0;
  const tableColumns = actions
    ? [
        ...columns,
        {
          title: "",
          key: "actions",
          fixed: "right" as const,
          width: actionsColumnWidth,
          render: (_: unknown, row: AnyRecord) => actions(row)
        }
      ]
    : columns;
  return (
    <section className="panel">
      <div className="panel-head">
        <Typography.Title level={4}>{title}</Typography.Title>
        <Space><Tag>{t("common.rows", { count })}</Tag><Button onClick={state.reload}>{t("common.refresh")}</Button></Space>
      </div>
      {state.error ? <Alert type="error" message={state.error} /> : (
        <Table
          size="small"
          rowKey={(row) => row.id || JSON.stringify(row)}
          loading={state.loading}
          dataSource={state.data || []}
          columns={tableColumns}
          onRow={onRow}
          pagination={state.pagination ? {
            current: Math.floor(state.pagination.offset / state.pagination.limit) + 1,
            pageSize: state.pagination.limit,
            total: state.pagination.total,
            showSizeChanger: true,
            onChange: (pageNumber, pageSize) => {
              state.pagination?.setPage(pageSize, (pageNumber - 1) * pageSize);
            },
          } : { pageSize: 8 }}
          scroll={{ x: true }}
        />
      )}
    </section>
  );
}

function mergeDirectoryUsers(
  baseUsers: DirectoryUserRecord[],
  nextUsers: DirectoryUserRecord[],
  orgNodes: AnyRecord[],
  roles: AnyRecord[],
) {
  /** Merge server and session users while hydrating org paths and role names where possible. */

  const roleNameById = new Map(roles.map((role) => [String(role.id), String(role.name)]));
  const orgPathById = new Map(orgNodes.map((node) => [String(node.id), String(node.path || "")]));
  const merged = new Map<string, DirectoryUserRecord>();

  for (const user of [...baseUsers, ...nextUsers]) {
    const key = String(user.id || user.user_id || user.external_ref || "");
    if (!key) continue;
    const roleIds = Array.from(new Set((user.role_ids || []).map(String)));
    const roleNames = user.role_names?.length
      ? user.role_names.map(String)
      : roleIds.map((roleId) => roleNameById.get(roleId)).filter(Boolean) as string[];
    const resolvedOrgNodeId = user.org_node_id
      ? String(user.org_node_id)
      : orgNodeIdForPath(orgNodes, user.org_path);
    const resolvedOrgPath = user.org_path ?? (resolvedOrgNodeId ? orgPathById.get(String(resolvedOrgNodeId)) || "" : "");
    merged.set(key, {
      ...user,
      org_node_id: resolvedOrgNodeId,
      role_ids: roleIds,
      role_names: roleNames,
      org_path: resolvedOrgPath,
      status: String(user.status || "active"),
    });
  }

  return Array.from(merged.values()).sort((left, right) => left.name.localeCompare(right.name));
}

function ImportPreviewPanel({
  importPreview,
  importFileName,
  t,
}: {
  importPreview: AnyRecord | null;
  importFileName: string;
  t: I18nContextValue["t"];
}) {
  /** Render one shared preview panel for both Excel and connector-driven imports. */

  return (
    <div className="directory-import-preview panel">
      <div className="panel-head">
        <Typography.Title level={4}>{t("users.previewSummary")}</Typography.Title>
        <Tag>{importFileName || t("users.uploadFile")}</Tag>
      </div>
      <div className="directory-import-preview-body">
        {importPreview ? (
          <>
            <div className="directory-preview-stats">
              <Statistic title={t("users.usersCreated")} value={Number(importPreview.summary?.created_users ?? importPreview.summary?.create_count ?? 0)} />
              <Statistic title={t("users.usersUpdated")} value={Number(importPreview.summary?.updated_users ?? importPreview.summary?.update_count ?? 0)} />
              <Statistic
                title={t("users.keysCreated")}
                value={Number(
                  importPreview.summary?.runtime_keys_created
                    ?? importPreview.summary?.created_users
                    ?? importPreview.summary?.create_count
                    ?? 0
                )}
              />
            </div>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label={t("users.orgNodesToCreate")}>
                {Array.isArray(importPreview.org_nodes_to_create || importPreview.org_nodes_created)
                  ? (importPreview.org_nodes_to_create || importPreview.org_nodes_created).join(", ") || "-"
                  : "-"}
              </Descriptions.Item>
              <Descriptions.Item label={t("users.rolesToCreate")}>
                {Array.isArray(importPreview.roles_to_create || importPreview.roles_created)
                  ? (importPreview.roles_to_create || importPreview.roles_created).join(", ") || "-"
                  : "-"}
              </Descriptions.Item>
            </Descriptions>
            <Table
              size="small"
              rowKey={(row) => `${row.external_ref}:${row.user_name}`}
              pagination={false}
              dataSource={Array.isArray(importPreview.users) ? importPreview.users : []}
              columns={[
                { title: columnLabel("name", t), dataIndex: "user_name", key: "user_name" },
                { title: columnLabel("external_ref", t), dataIndex: "external_ref", key: "external_ref" },
                {
                  title: columnLabel("org_path", t),
                  dataIndex: "org_path",
                  key: "org_path",
                  render: (value: string | null | undefined) => String(value || "-"),
                },
                {
                  title: columnLabel("role_names", t),
                  dataIndex: "roles",
                  key: "roles",
                  render: (value: string[] | string) =>
                    Array.isArray(value) ? value.join(", ") || "-" : String(value || "-"),
                },
              ]}
            />
          </>
        ) : (
          <Empty description={t("users.importReady")} />
        )}
      </div>
    </div>
  );
}

function buildOrgTree(orgNodes: AnyRecord[]): OrgTreeNode[] {
  /** Convert flat org-node rows into one rooted tree with a stable / node. */

  const nodes = new Map<string, OrgTreeNode>();
  let rootNode: OrgTreeNode | null = null;
  for (const orgNode of orgNodes) {
    const directUserNames = Array.isArray(orgNode.direct_user_names)
      ? orgNode.direct_user_names.map(String)
      : [];
    const node = {
      key: String(orgNode.id),
      title: String(orgNode.path || "") ? String(orgNode.name || orgNode.path) : "/",
      path: String(orgNode.path || ""),
      parentId: orgNode.parent_id ? String(orgNode.parent_id) : null,
      isRoot: String(orgNode.path || "") === "",
      directUserNames,
      children: [],
    };
    nodes.set(String(orgNode.id), node);
    if (node.isRoot) {
      rootNode = node;
    }
  }
  if (!rootNode) return [];
  for (const orgNode of orgNodes) {
    const node = nodes.get(String(orgNode.id));
    if (!node) continue;
    const parentId = orgNode.parent_id ? String(orgNode.parent_id) : "";
    if (node.isRoot) continue;
    if (parentId && nodes.has(parentId)) {
      nodes.get(parentId)?.children?.push(node);
    } else {
      rootNode.children?.push(node);
    }
  }
  return [rootNode];
}

function toOrgTreeData(
  nodes: OrgTreeNode[],
  t: I18nContextValue["t"],
  actions: {
    onCreateNode: (node: OrgTreeNode) => void;
    onCreateSibling: (node: OrgTreeNode) => void;
    onCreateChild: (node: OrgTreeNode) => void;
    onEditNode: (node: OrgTreeNode) => void;
    onDeleteNode: (node: OrgTreeNode) => void;
    onSelectNode: (node: OrgTreeNode) => void;
  },
): AnyRecord[] {
  /** Decorate org nodes with direct-member names and per-node context actions. */

  return nodes.map((node) => {
    const isLeaf = !node.children?.length;
    const directUsers = node.directUserNames || [];
    const menuItems = node.isRoot
      ? [
          {
            key: "create-root-node",
            label: t("users.orgCreateRoot"),
            onClick: () => actions.onCreateNode(node),
          },
        ]
      : [
          {
            key: "create-sibling-node",
            label: t("users.orgCreateSibling"),
            onClick: () => actions.onCreateSibling(node),
          },
          {
            key: "create-child-node",
            label: t("users.orgCreateChild"),
            onClick: () => actions.onCreateChild(node),
          },
          {
            key: "edit-node",
            label: t("users.orgEdit"),
            onClick: () => actions.onEditNode(node),
          },
          {
            key: "delete-node",
            label: t("users.orgDelete"),
            onClick: () => actions.onDeleteNode(node),
          },
        ];
    return {
      key: node.key,
      title: (
        <Dropdown
          trigger={["contextMenu"]}
          menu={{
            items: menuItems.map((item) => ({ key: item.key, label: item.label })),
            onClick: ({ key }) => {
              const item = menuItems.find((entry) => entry.key === key);
              actions.onSelectNode(node);
              item?.onClick();
            },
          }}
        >
          <div className="directory-tree-node" onContextMenu={() => actions.onSelectNode(node)}>
            <span className="directory-tree-node-name">{node.title}</span>
            {isLeaf && directUsers.length ? (
              <Typography.Text type="secondary" className="directory-tree-node-members">
                {directUsers.join(", ")}
              </Typography.Text>
            ) : null}
          </div>
        </Dropdown>
      ),
      children: toOrgTreeData(node.children || [], t, actions),
    };
  });
}

function collectOrgDescendantIds(orgNodes: AnyRecord[], orgNodeId: string) {
  /** Collect one org node and all descendant ids for user filtering. */

  const childrenByParent = new Map<string, string[]>();
  for (const orgNode of orgNodes) {
    const parentId = orgNode.parent_id ? String(orgNode.parent_id) : "";
    if (!childrenByParent.has(parentId)) {
      childrenByParent.set(parentId, []);
    }
    childrenByParent.get(parentId)?.push(String(orgNode.id));
  }

  const pending = [orgNodeId];
  const visited = new Set<string>();
  while (pending.length) {
    const current = pending.pop();
    if (!current || visited.has(current)) continue;
    visited.add(current);
    for (const childId of childrenByParent.get(current) || []) {
      pending.push(childId);
    }
  }
  return visited;
}

function pathForOrgNode(orgNodes: AnyRecord[], orgNodeId: unknown) {
  /** Resolve an org-node id to its display path. */

  const key = orgNodeId ? String(orgNodeId) : "";
  if (!key) return "";
  const match = orgNodes.find((node) => String(node.id) === key);
  return match ? String(match.path || "") : "";
}

function orgNodeIdForPath(orgNodes: AnyRecord[], orgPath: unknown) {
  /** Resolve an org path string back to a node id when available. */

  const path = String(orgPath || "");
  const match = orgNodes.find((node) => String(node.path || "") === path);
  return match ? String(match.id) : null;
}

function roleIdsForNames(roles: AnyRecord[], roleNames: string[]) {
  /** Convert display role names back into known role ids where possible. */

  const ids: string[] = [];
  for (const roleName of roleNames) {
    const match = roles.find((role) => String(role.name) === roleName);
    if (match) {
      ids.push(String(match.id));
    }
  }
  return ids;
}

function columnsFromRows(rows: AnyRecord[], t: I18nContextValue["t"]): ColumnsType<AnyRecord> {
  /** Infer table columns from backend rows while hiding technical foreign keys. */

  const hiddenKeys = new Set(["id", "datasource_id", "resource_id", "api_key_id"]);
  const keys = Array.from(new Set(rows.flatMap((row) => Object.keys(row))))
    .filter((key) => !hiddenKeys.has(key))
    .slice(0, 8);
  return keys.map((key) => ({
    title: columnLabel(key, t),
    dataIndex: key,
    ellipsis: true,
    render: (value: unknown) => {
      if (typeof value === "object" && value !== null) {
        return JSON.stringify(value);
      }
      if (typeof value === "string") {
        return optionLabel(value, t);
      }
      return String(value ?? "");
    }
  }));
}

function auditColumns(t: I18nContextValue["t"]): ColumnsType<AnyRecord> {
  /** Keep audit tables operator-readable while preserving raw identifiers for details. */

  return [
    {
      title: columnLabel("user_name", t),
      dataIndex: "user_name",
      key: "user_name",
      ellipsis: true,
      render: (value: unknown, row: AnyRecord) => String(value || row.user_id || ""),
    },
    {
      title: columnLabel("event_type", t),
      dataIndex: "event_type",
      key: "event_type",
      ellipsis: true,
      render: (value: unknown) => optionLabel(String(value || ""), t),
    },
    {
      title: columnLabel("resource_ids", t),
      dataIndex: "resource_ids",
      key: "resource_ids",
      ellipsis: true,
      render: (value: unknown) => (typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "")),
    },
    {
      title: columnLabel("decision", t),
      dataIndex: "decision",
      key: "decision",
      ellipsis: true,
      render: (value: unknown) => optionLabel(String(value || ""), t),
    },
    {
      title: columnLabel("reason", t),
      dataIndex: "reason",
      key: "reason",
      ellipsis: true,
      render: (value: unknown) => optionLabel(String(value || ""), t),
    },
    {
      title: columnLabel("query_id", t),
      dataIndex: "query_id",
      key: "query_id",
      ellipsis: true,
      render: (value: unknown) => String(value ?? ""),
    },
    {
      title: columnLabel("created_at", t),
      dataIndex: "created_at",
      key: "created_at",
      ellipsis: true,
      render: (value: unknown) => String(value ?? ""),
    },
  ];
}

function IconAction({ title, icon, onClick }: { title: string; icon: React.ReactNode; onClick: () => void }) {
  /** Render a compact icon button with an accessible tooltip label. */

  return (
    <Tooltip title={title}>
      <Button size="small" aria-label={title} icon={icon} onClick={onClick} />
    </Tooltip>
  );
}

function RecordDetails({
  record,
  title,
  onClose,
  extraItems,
  hiddenKeys,
  width = 560
}: {
  record: AnyRecord | null;
  title: string;
  onClose: () => void;
  extraItems?: Array<{ key: string; label: React.ReactNode; children: React.ReactNode }>;
  hiddenKeys?: string[];
  width?: number;
}) {
  /** Show all fields of a selected row in a copy-friendly details drawer. */

  const { t } = useI18n();
  const hiddenDetailKeys = new Set([
    "policy_items",
    "policy_ids",
    "datasource_ids",
    "resource_ids",
    "tag_ids",
    "datasource_labels",
    "resource_labels",
    "tag_names",
    "effect_values",
    "action_values",
    "allow_decrypt_values",
    "status_values",
    ...(hiddenKeys || []),
  ]);
  return (
    <Drawer title={t("common.detailsTitle", { title })} open={Boolean(record)} onClose={onClose} width={width}>
      {record ? (
        <Descriptions bordered column={1} size="small">
          {Object.entries(record).filter(([key]) => !hiddenDetailKeys.has(key)).map(([key, value]) => (
            <Descriptions.Item key={key} label={columnLabel(key, t)}>
              <Typography.Text copyable={typeof value === "string"}>
                {typeof value === "object" && value !== null ? JSON.stringify(value) : typeof value === "string" ? optionLabel(value, t) : String(value ?? "")}
              </Typography.Text>
            </Descriptions.Item>
          ))}
          {(extraItems || []).map((item) => (
            <Descriptions.Item key={item.key} label={item.label}>
              {item.children}
            </Descriptions.Item>
          ))}
        </Descriptions>
      ) : null}
    </Drawer>
  );
}

type ResourceScopeTransferItem = {
  key: string;
  title: string;
  searchText: string;
};

function ResourceScopeTransfer({
  datasources,
  resources,
  loading,
  t,
  value,
  onChange,
}: {
  datasources: AnyRecord[];
  resources: AnyRecord[];
  loading?: boolean;
  t: I18nContextValue["t"];
  value?: string[];
  onChange?: (value?: string[]) => void;
}) {
  /** Tree transfer for selecting one or more datasource/resource policy scopes. */

  const selectedKeys = normalizeResourceScopeKeys(value);
  const [resourceSearch, setResourceSearch] = useState("");
  const [selectedResourceSearch, setSelectedResourceSearch] = useState("");
  const [expandedResourceKeys, setExpandedResourceKeys] = useState<React.Key[]>([]);
  const [expandedSelectedResourceKeys, setExpandedSelectedResourceKeys] = useState<React.Key[]>([]);
  const { treeData, transferItems } = useMemo(
    () => buildResourceScopeTransferData(datasources, resources),
    [datasources, resources],
  );
  const selectedTreeData = filterResourceScopeTree(treeData, new Set(selectedKeys));
  const renderResourceTransferTitle = (
    title: string,
    treeNodes: TreeDataNode[],
    onExpandAll: () => void,
    onCollapseAll: () => void,
  ) => {
    const disabled = loading || treeNodes.length === 0;
    return (
      <span className="resource-transfer-list-title">
        <span className="resource-transfer-list-title-label">{title}</span>
        <span className="resource-transfer-list-title-actions">
          <Tooltip title={t("policy.expandAllResources")}>
            <Button
              aria-label={`${title} ${t("policy.expandAllResources")}`}
              icon={<ExpandAltOutlined />}
              size="small"
              onClick={onExpandAll}
              disabled={disabled}
            />
          </Tooltip>
          <Tooltip title={t("policy.collapseAllResources")}>
            <Button
              aria-label={`${title} ${t("policy.collapseAllResources")}`}
              icon={<ShrinkOutlined />}
              size="small"
              onClick={onCollapseAll}
              disabled={disabled}
            />
          </Tooltip>
        </span>
      </span>
    );
  };

  return (
    <div className="resource-tree-transfer-wrap">
      <Transfer<ResourceScopeTransferItem>
        className="resource-tree-transfer"
        dataSource={transferItems}
        targetKeys={selectedKeys}
        titles={[
          renderResourceTransferTitle(
            t("policy.availableResources"),
            treeData,
            () => setExpandedResourceKeys(collectTreeKeys(treeData)),
            () => setExpandedResourceKeys([]),
          ),
          renderResourceTransferTitle(
            t("policy.selectedResources"),
            selectedTreeData,
            () => setExpandedSelectedResourceKeys(collectTreeKeys(selectedTreeData)),
            () => setExpandedSelectedResourceKeys([]),
          ),
        ]}
        render={(item) => <span className="resource-transfer-item-title" title={item.title}>{item.title}</span>}
        onChange={(nextKeys) => onChange?.(nextKeys.map(String))}
        listStyle={{ height: 360, maxHeight: 360 }}
        showSearch
        locale={{
          searchPlaceholder: t("policy.searchResources"),
          itemUnit: t("policy.resourceItemUnit"),
          itemsUnit: t("policy.resourceItemsUnit"),
        }}
        filterOption={(input, item) => item.searchText.toLowerCase().includes(input.toLowerCase())}
        onSearch={(direction, input) => {
          if (direction === "left") {
            setResourceSearch(input);
          } else {
            setSelectedResourceSearch(input);
          }
        }}
        showSelectAll={false}
        disabled={loading}
      >
        {({ direction, filteredItems, onItemSelect, selectedKeys: transferSelectedKeys }) => {
          const isSourceList = direction === "left";
          const baseTreeData = isSourceList ? treeData : selectedTreeData;
          const searchValue = isSourceList ? resourceSearch : selectedResourceSearch;
          const expandedState = isSourceList ? expandedResourceKeys : expandedSelectedResourceKeys;
          const setExpandedState = isSourceList ? setExpandedResourceKeys : setExpandedSelectedResourceKeys;
          const checkedKeys = isSourceList
            ? [...transferSelectedKeys.map(String), ...selectedKeys]
            : transferSelectedKeys.map(String);
          const filteredKeys = new Set(filteredItems.map((item) => String(item.key)));
          const isSearchingResources = Boolean(searchValue.trim());
          const visibleTreeData = isSearchingResources
            ? filterResourceScopeTree(baseTreeData, filteredKeys)
            : baseTreeData;
          const expandedKeys = isSearchingResources ? collectTreeKeys(visibleTreeData) : expandedState;
          const selectableKeys = new Set(selectedKeys);
          const renderedTreeData = isSourceList
            ? markSelectedTreeNodes(visibleTreeData, selectedKeys)
            : markUnselectedContextTreeNodes(visibleTreeData, selectableKeys);
          if (!isSourceList && visibleTreeData.length === 0) {
            return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
          }
          return (
            <Tree
              key={`${direction}-${isSearchingResources ? "resource-filtered-tree" : "resource-tree"}`}
              blockNode
              checkable
              checkStrictly
              checkedKeys={checkedKeys}
              expandedKeys={expandedKeys}
              treeData={renderedTreeData}
              onExpand={(_, info) => {
                if (!isSearchingResources) {
                  setExpandedState((currentKeys) => {
                    const nextKeys = new Set(currentKeys.map(String));
                    const key = String(info.node.key);
                    if (nextKeys.has(key)) {
                      nextKeys.delete(key);
                    } else {
                      nextKeys.add(key);
                    }
                    return Array.from(nextKeys);
                  });
                }
              }}
              onCheck={(_, info) => {
                const key = String(info.node.key);
                if (!isSourceList && !selectableKeys.has(key)) {
                  return;
                }
                onItemSelect(key, !checkedKeys.includes(key));
              }}
              onSelect={(_, info) => {
                const key = String(info.node.key);
                if (!isSourceList && !selectableKeys.has(key)) {
                  return;
                }
                onItemSelect(key, !checkedKeys.includes(key));
              }}
            />
          );
        }}
      </Transfer>
    </div>
  );
}

function ResourcePolicyScopeDetails({
  policy,
  datasources,
  resources,
  tags,
  t,
}: {
  policy: AnyRecord;
  datasources: AnyRecord[];
  resources: AnyRecord[];
  tags: AnyRecord[];
  t: I18nContextValue["t"];
}) {
  /** Read-only view of a grouped resource policy's selected authorization scopes. */

  const scopeKeys = resourceScopeKeysFromPolicy(policy);
  const [expandedScopeKeys, setExpandedScopeKeys] = useState<React.Key[]>([]);
  const { treeData } = useMemo(
    () => buildResourceScopeTransferData(datasources, resources),
    [datasources, resources],
  );
  useEffect(() => {
    setExpandedScopeKeys([]);
  }, [policy.id]);
  const selectedTreeData = filterResourceScopeTree(treeData, new Set(scopeKeys));
  const tagLabels = resourcePolicyTagLabels(policy, tags);
  const toggleScopeKey = (key: React.Key) => {
    setExpandedScopeKeys((currentKeys) => {
      const keyString = String(key);
      const currentKeyStrings = currentKeys.map(String);
      if (currentKeyStrings.includes(keyString)) {
        return currentKeys.filter((item) => String(item) !== keyString);
      }
      return [...currentKeys, key];
    });
  };
  const renderScopeTreeTitle = (node: TreeDataNode) => {
    const hasChildren = Array.isArray(node.children) && node.children.length > 0;
    if (!hasChildren) {
      return node.title as React.ReactNode;
    }
    return (
      <span
        className="resource-policy-scope-tree-title"
        onClick={(event) => {
          event.stopPropagation();
          toggleScopeKey(node.key);
        }}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            toggleScopeKey(node.key);
          }
        }}
        role="button"
        tabIndex={0}
      >
        {node.title as React.ReactNode}
      </span>
    );
  };
  if (selectedTreeData.length === 0 && tagLabels.length === 0) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  }
  return (
    <Space direction="vertical" size={12} className="resource-policy-scope-detail">
      {selectedTreeData.length > 0 ? (
        <Tree
          key={`resource-policy-scope-${String(policy.id ?? scopeKeys.join("|"))}`}
          blockNode
          className="resource-policy-scope-tree"
          autoExpandParent={false}
          expandedKeys={expandedScopeKeys}
          onExpand={(nextKeys) => {
            setExpandedScopeKeys(nextKeys);
          }}
          selectable={false}
          showLine
          titleRender={renderScopeTreeTitle}
          treeData={selectedTreeData}
        />
      ) : null}
      {tagLabels.length > 0 ? (
        <div className="resource-policy-scope-tags">
          <Typography.Text type="secondary">{t("tab.tag")}</Typography.Text>
          <Space size={[4, 4]} wrap>
            {tagLabels.map((label) => <Tag key={label}>{label}</Tag>)}
          </Space>
        </div>
      ) : null}
    </Space>
  );
}

function buildResourceScopeTransferData(
  datasources: AnyRecord[],
  resources: AnyRecord[],
) {
  /** Build datasource roots and resource child nodes for the policy scope transfer. */

  const datasourceNodes = new Map<string, TreeDataNode & { children: TreeDataNode[] }>();
  const transferItems: ResourceScopeTransferItem[] = [];
  const ensureDatasourceNode = (datasourceId: string, fallbackName?: string) => {
    const existing = datasourceNodes.get(datasourceId);
    if (existing) {
      return existing;
    }
    const datasource = datasources.find((item) => item.id === datasourceId);
    const title = String(datasource?.name || fallbackName || datasourceId);
    const node: TreeDataNode & { children: TreeDataNode[] } = {
      key: resourceScopeKey("datasource", datasourceId),
      title: resourceTreeTitle(title),
      children: [],
    };
    datasourceNodes.set(datasourceId, node);
    transferItems.push({
      key: String(node.key),
      title,
      searchText: `${title} ${datasourceId}`,
    });
    return node;
  };

  datasources.forEach((datasource) => {
    ensureDatasourceNode(String(datasource.id), String(datasource.name || datasource.id));
  });

  const resourceNodes = new Map<string, TreeDataNode & { children: TreeDataNode[] }>();
  resources.forEach((resource) => {
    const resourceId = String(resource.id);
    const label = resourceDisplayLabel(resource);
    const kind = String(resource.kind || "");
    const node: TreeDataNode & { children: TreeDataNode[] } = {
      key: resourceScopeKey("resource", resourceId),
      title: resourceTreeTitle(label),
      children: [],
    };
    resourceNodes.set(resourceId, node);
    transferItems.push({
      key: String(node.key),
      title: label,
      searchText: `${label} ${kind} ${resourceId}`,
    });
  });

  resources.forEach((resource) => {
    const resourceId = String(resource.id);
    const node = resourceNodes.get(resourceId);
    if (!node) {
      return;
    }
    const parentId = resource.parent_id ? String(resource.parent_id) : "";
    const parentNode = parentId ? resourceNodes.get(parentId) : undefined;
    if (parentNode) {
      parentNode.children.push(node);
      return;
    }
    const datasourceId = String(resource.datasource_id || "");
    if (datasourceId) {
      ensureDatasourceNode(datasourceId).children.push(node);
    }
  });

  return {
    treeData: Array.from(datasourceNodes.values()),
    transferItems,
  };
}

function markSelectedTreeNodes(
  nodes: TreeDataNode[],
  selectedKeys: string[],
): TreeDataNode[] {
  /** Disable nodes already moved to the selected side, matching Ant Design's Tree Transfer pattern. */

  const selected = new Set(selectedKeys);
  return nodes.map((node) => ({
    ...node,
    disabled: selected.has(String(node.key)),
    children: node.children ? markSelectedTreeNodes(node.children, selectedKeys) : undefined,
  }));
}

function markUnselectedContextTreeNodes(
  nodes: TreeDataNode[],
  selectedKeys: Set<string>,
): TreeDataNode[] {
  /** In the selected-side tree, ancestors are context only unless they are selected scopes themselves. */

  return nodes.map((node) => {
    const isSelected = selectedKeys.has(String(node.key));
    return {
      ...node,
      disableCheckbox: !isSelected,
      selectable: isSelected,
      children: node.children ? markUnselectedContextTreeNodes(node.children, selectedKeys) : undefined,
    };
  });
}

function filterResourceScopeTree(
  nodes: TreeDataNode[],
  matchingKeys: Set<string>,
): TreeDataNode[] {
  /** Keep matching tree nodes and their ancestors for transfer search results. */

  return nodes.flatMap((node) => {
    const children = node.children ? filterResourceScopeTree(node.children, matchingKeys) : [];
    if (matchingKeys.has(String(node.key)) || children.length > 0) {
      return [{
        ...node,
        children,
      }];
    }
    return [];
  });
}

function collectTreeKeys(nodes: TreeDataNode[]): string[] {
  /** Collect keys so filtered results reveal their matching descendants. */

  return nodes.flatMap((node) => [
    String(node.key),
    ...(node.children ? collectTreeKeys(node.children) : []),
  ]);
}

function resourceTreeTitle(title: string) {
  /** Wrap long tree node names without adding redundant type prefixes. */

  return <span className="resource-tree-node-title" title={title}>{title}</span>;
}

function resourceDisplayLabel(resource: AnyRecord) {
  /** Human-facing label for a datasource resource node. */

  return String(resource.display_name || resource.name || resource.id);
}

function resourceScopeKey(type: "datasource" | "resource", id: string) {
  /** Stable key namespace used by the mixed datasource/resource transfer. */

  return `${type}:${id}`;
}

function normalizeResourceScopeKeys(value: unknown) {
  /** Normalize Ant Design form values into transfer target keys. */

  if (!Array.isArray(value)) {
    return [];
  }
  return value.map(String).filter((item) => item.startsWith("datasource:") || item.startsWith("resource:"));
}

function splitResourceScopeKeys(value: unknown) {
  /** Split transfer target keys into backend batch payload arrays. */

  const datasourceIds: string[] = [];
  const resourceIds: string[] = [];
  normalizeResourceScopeKeys(value).forEach((key) => {
    const separatorIndex = key.indexOf(":");
    const type = key.slice(0, separatorIndex);
    const id = key.slice(separatorIndex + 1);
    if (separatorIndex < 0 || !id) {
      return;
    }
    if (type === "datasource") {
      datasourceIds.push(id);
    } else if (type === "resource") {
      resourceIds.push(id);
    }
  });
  return { datasourceIds, resourceIds };
}

function resourceScopeKeysFromPolicy(row: AnyRecord) {
  /** Convert one grouped policy row into tree transfer target keys for editing. */

  const keys: string[] = [];
  const addDatasourceId = (datasourceId: unknown) => {
    if (datasourceId) {
      keys.push(resourceScopeKey("datasource", String(datasourceId)));
    }
  };
  const addResourceId = (resourceId: unknown) => {
    if (resourceId) {
      keys.push(resourceScopeKey("resource", String(resourceId)));
    }
  };

  if (Array.isArray(row.datasource_ids)) {
    row.datasource_ids.forEach(addDatasourceId);
  }
  if (Array.isArray(row.resource_ids)) {
    row.resource_ids.forEach(addResourceId);
  }
  if (Array.isArray(row.policy_items)) {
    row.policy_items.forEach((policy: AnyRecord) => {
      addDatasourceId(policy.datasource_id);
      addResourceId(policy.resource_id);
    });
  }
  if (row.datasource_id) {
    addDatasourceId(row.datasource_id);
  }
  if (row.resource_id) {
    addResourceId(row.resource_id);
  }
  return Array.from(new Set(keys));
}

function resourcePolicyScopeCount(row: AnyRecord, countKey: string, idsKey: string, legacyIdKey: string) {
  /** Prefer backend grouped counts, while keeping older payload shapes readable. */

  const rawCount = row[countKey];
  if (typeof rawCount === "number" && Number.isFinite(rawCount)) {
    return rawCount;
  }
  if (Array.isArray(row[idsKey])) {
    return row[idsKey].filter(Boolean).length;
  }
  return row[legacyIdKey] ? 1 : 0;
}

function resourcePolicyScopeCountText(
  row: AnyRecord,
  countKey: string,
  idsKey: string,
  legacyIdKey: string,
  t: I18nContextValue["t"],
) {
  /** Render compact grouped-scope counts in policy tables instead of long name joins. */

  const count = resourcePolicyScopeCount(row, countKey, idsKey, legacyIdKey);
  if (count <= 0) {
    return "-";
  }
  return `${count} ${count === 1 ? t("policy.resourceItemUnit") : t("policy.resourceItemsUnit")}`;
}

function resourcePolicyTagLabels(row: AnyRecord, tags: AnyRecord[]) {
  /** Resolve tag-scope display names from grouped policy rows and loaded tag metadata. */

  const ids: string[] = [];
  const addTagId = (tagId: unknown) => {
    if (tagId) {
      ids.push(String(tagId));
    }
  };
  if (Array.isArray(row.tag_ids)) {
    row.tag_ids.forEach(addTagId);
  }
  if (Array.isArray(row.policy_items)) {
    row.policy_items.forEach((policy: AnyRecord) => addTagId(policy.tag_id));
  }
  addTagId(row.tag_id);

  const names = Array.isArray(row.tag_names)
    ? row.tag_names.map(String).filter(Boolean)
    : row.tag_name
      ? [String(row.tag_name)]
      : [];
  const tagNameById = new Map(tags.map((tag) => [String(tag.id), String(tag.name || tag.id)]));
  const labels = ids.length > 0
    ? ids.map((id, index) => tagNameById.get(id) || names[index] || id)
    : names;
  return Array.from(new Set(labels));
}

function tagIdFromPolicy(row: AnyRecord) {
  /** Resolve the primary tag value from grouped or legacy resource policy rows. */

  if (Array.isArray(row.tag_ids) && row.tag_ids.length > 0) {
    return String(row.tag_ids[0]);
  }
  if (Array.isArray(row.policy_items)) {
    const policyWithTag = row.policy_items.find((policy: AnyRecord) => policy.tag_id);
    if (policyWithTag?.tag_id) {
      return String(policyWithTag.tag_id);
    }
  }
  return row.tag_id;
}

function resourcePolicyTargetMode(row: AnyRecord): PolicyTargetMode {
  /** Prefer resource-scope editing unless a grouped policy only contains tag scopes. */

  const hasResourceScope = resourceScopeKeysFromPolicy(row).length > 0;
  const hasTagScope = Boolean(tagIdFromPolicy(row));
  return hasTagScope && !hasResourceScope ? "tag" : "resource";
}

function isGroupedResourcePolicyRow(row: AnyRecord) {
  /** Backend grouped resource policy rows represent a whole subject, not one policy id. */

  return Array.isArray(row.policy_ids) || Array.isArray(row.policy_items) || String(row.id || "").startsWith("subject:");
}

function ResourceSelect({
  resources,
  loading,
  selectableKinds,
  t,
  value,
  onChange,
  id
}: {
  resources: AnyRecord[];
  loading?: boolean;
  selectableKinds?: string[];
  t: I18nContextValue["t"];
  value?: string;
  onChange?: (value?: string) => void;
  id?: string;
}) {
  /** Searchable resource picker used by policy and masking forms. */

  const kindFilter = selectableKinds ? new Set(selectableKinds) : null;
  const options = resources.filter((resource) => {
    const kind = String(resource.kind || "");
    return kindFilter === null || kindFilter.has(kind);
  }).map((resource) => {
    const name = String(resource.display_name || resource.name || resource.id);
    const path = String(resource.path || "");
    const kind = String(resource.kind || "");
    const label = `${optionLabel(kind, t)}: ${[name, path].filter(Boolean).join(" / ")}`;
    return {
      value: resource.id,
      label,
      searchText: `${name} ${path} ${kind} ${resource.id}`
    };
  });
  return (
    <Select
      id={id}
      value={value}
      onChange={onChange}
      showSearch
      allowClear
      loading={loading}
      className="resource-select"
      placeholder={t("placeholder.resourceSearch")}
      options={options}
      filterOption={(input, option) =>
        String((option as { searchText?: string } | undefined)?.searchText || "")
          .toLowerCase()
          .includes(input.toLowerCase())
      }
    />
  );
}

function TagSelect({
  tags,
  t,
  value,
  onChange,
}: {
  tags: AnyRecord[];
  t: I18nContextValue["t"];
  value?: string;
  onChange?: (value?: string) => void;
}) {
  /** Searchable tag picker used by tag-scoped resource policies. */

  return (
    <Select
      value={value}
      onChange={onChange}
      showSearch
      allowClear
      placeholder={t("placeholder.tagSearch")}
      options={tags.map((tag) => ({
        value: tag.id,
        label: tag.name,
      }))}
      optionFilterProp="label"
    />
  );
}

function PolicySubjectSelect({
  subjectType,
  users,
  roles,
  t,
  value,
  onChange,
}: {
  subjectType: string;
  users: DirectoryUserRecord[];
  roles: AnyRecord[];
  t: I18nContextValue["t"];
  value?: string;
  onChange?: (value?: string) => void;
}) {
  /** Pick one user or role for policy subjects without typing raw ids. */

  if (subjectType === "all") {
    return <Input value={t("option.all")} disabled aria-label={t("field.subject")} />;
  }

  const options = subjectType === "role"
    ? roles.map((role) => ({ value: role.id, label: role.name }))
    : users.map((user) => ({
        value: user.id || user.user_id,
        label: `${user.name}${user.org_path ? ` / ${user.org_path}` : ""}`,
      }));

  return (
    <Select
      value={value}
      onChange={onChange}
      showSearch
      allowClear
      placeholder={t("field.subject")}
      options={options}
      optionFilterProp="label"
    />
  );
}

function normalizePolicyValues(
  values: AnyRecord,
  targetMode: PolicyTargetMode,
  isField: boolean,
  options: { batch?: boolean } = {},
) {
  /** Normalize policy forms so resource and tag targeting remain mutually exclusive. */

  const payload: AnyRecord = {
    subject_type: values.subject_type,
    subject_id: values.subject_type === "all" ? "all" : values.subject_id,
    effect: values.effect,
    action: values.action,
    status: values.status || "active",
  };

  if (isField) {
    payload.resource_id = values.resource_id;
    payload.field_name = String(values.field_name || "").trim();
    return payload;
  }

  payload.allow_decrypt = values.effect === "allow" && Boolean(values.allow_decrypt);
  if (targetMode === "resource") {
    const { datasourceIds, resourceIds } = splitResourceScopeKeys(values.resource_scope_keys);
    if (options.batch) {
      payload.datasource_ids = datasourceIds;
      payload.resource_ids = resourceIds;
      payload.tag_ids = [];
    } else {
      payload.datasource_id = datasourceIds[0] || null;
      payload.resource_id = resourceIds[0] || null;
      payload.tag_id = null;
    }
    return payload;
  }

  if (options.batch) {
    payload.datasource_ids = [];
    payload.resource_ids = [];
    payload.tag_ids = values.tag_id ? [values.tag_id] : [];
    return payload;
  }

  payload.datasource_id = null;
  payload.resource_id = null;
  payload.tag_id = values.tag_id;
  return payload;
}

function renderField(field: FieldConfig, t: I18nContextValue["t"]) {
  /** Convert declarative field config into the matching Ant Design form control. */

  const label = t(field.label);
  const rules = field.required ? [{ required: true, message: t("common.required", { label }) }] : undefined;
  let control: React.ReactNode = <Input autoComplete="off" />;
  if (field.input === "textarea") {
    control = <Input.TextArea autoComplete="off" autoSize={{ minRows: 3, maxRows: 8 }} />;
  } else if (field.input === "number") {
    control = <InputNumber className="full" />;
  } else if (field.input === "tags") {
    control = <Select mode="tags" />;
  } else if (field.input === "select") {
    control = <Select options={(field.options || []).map((value) => ({ label: optionLabel(value, t), value }))} />;
  } else if (field.input === "resource-select") {
    control = <ResourceSelect resources={field.resourceOptions || []} loading={field.loading} t={t} />;
  }
  return (
    <Form.Item key={field.name} name={field.name} label={label} rules={rules}>
      {control}
    </Form.Item>
  );
}

function toFormValues(values: AnyRecord, fields: FieldConfig[]) {
  /** Return shallow-copied values so generic drawers can edit API payloads safely. */

  void fields;
  return { ...values };
}

function normalizeValues(values: AnyRecord, fields: FieldConfig[], t?: I18nContextValue["t"]) {
  /** Return shallow-copied values for generic CRUD forms without JSON text parsing. */

  void fields;
  void t;
  return { ...values };
}

function AuditEventsPage({ api }: { api: ReturnType<typeof useApi> }) {
  /** Keep the audit list summary-only and fetch raw SQL through the dedicated endpoint. */

  const { t } = useI18n();
  const state = useData<AnyRecord[]>((page) => api.request(paginatedPath("/admin/audit-events", page)), [api.apiKey], { paginated: true });
  const [selected, setSelected] = useState<AnyRecord | null>(null);
  const [sqlRecord, setSqlRecord] = useState<AnyRecord | null>(null);
  const [sqlError, setSqlError] = useState<string | null>(null);
  const [sqlLoading, setSqlLoading] = useState(false);
  const titleText = t("nav.audit");
  const columns = auditColumns(t);

  const openAuditDetails = async (row: AnyRecord) => {
    setSelected(row);
    setSqlRecord(null);
    setSqlLoading(true);
    setSqlError(null);
    try {
      setSqlRecord(await api.request<AnyRecord>(`/admin/audit-events/${row.id}/sql`));
      state.reload();
    } catch (error) {
      setSqlRecord(null);
      setSqlError(error instanceof Error ? error.message : String(error));
    } finally {
      setSqlLoading(false);
    }
  };

  const closeAuditDetails = () => {
    setSelected(null);
    setSqlRecord(null);
    setSqlError(null);
    setSqlLoading(false);
  };

  const auditSqlDetail = selected
    ? [{
        key: "raw-sql",
        label: t("audit.rawSql"),
        children: sqlError ? (
          <Alert type="error" message={sqlError} />
        ) : sqlLoading ? (
          <Typography.Text type="secondary">{t("common.refresh")}</Typography.Text>
        ) : sqlRecord?.sql_text ? (
          <Typography.Paragraph copyable>
            <pre>{String(sqlRecord.sql_text)}</pre>
          </Typography.Paragraph>
        ) : (
          <Typography.Text type="secondary">{t("audit.emptySql")}</Typography.Text>
        ),
      }]
    : undefined;

  return (
    <>
      <DataPanel
        title={titleText}
        state={state}
        columns={columns}
        actions={(row) => (
          <Space size={6}>
            <IconAction title={t("audit.viewDetails")} icon={<EyeOutlined />} onClick={() => void openAuditDetails(row)} />
          </Space>
        )}
      />
      <RecordDetails
        record={selected}
        title={titleText}
        onClose={closeAuditDetails}
        extraItems={auditSqlDetail}
        width={720}
      />
    </>
  );
}

declare global {
  interface Window {
    __adgRoot?: ReactDOM.Root;
    __adgRootElement?: HTMLElement | null;
  }
}

const appRootElement = document.getElementById("root") as HTMLElement | null;
if (appRootElement) {
  const staleRootElement = window.__adgRootElement;
  if (window.__adgRoot && staleRootElement && !staleRootElement.isConnected) {
    window.__adgRoot = undefined;
    window.__adgRootElement = undefined;
  } else if (window.__adgRoot && staleRootElement !== appRootElement) {
    window.__adgRoot.unmount();
    window.__adgRoot = undefined;
    window.__adgRootElement = undefined;
  }
  const appRoot = window.__adgRoot ?? ReactDOM.createRoot(appRootElement);
  window.__adgRoot = appRoot;
  window.__adgRootElement = appRootElement;
  appRoot.render(<App />);
}
