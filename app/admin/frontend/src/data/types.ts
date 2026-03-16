export interface FieldConfig {
  name: string;
  type: string;
  editable: boolean;
  required: boolean;
  options?: string[] | null;
}

export interface ModelConfig {
  label: string;
  has_password_change: boolean;
  fields: FieldConfig[];
}

export interface AppConfig {
  label: string;
  models: Record<string, ModelConfig>;
}

export type AppsRegistry = Record<string, AppConfig>;

export type RecordData = Record<string, unknown>;
