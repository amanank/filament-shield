<?php

declare(strict_types=1);

namespace BezhanSalleh\FilamentShield\Traits;

use BezhanSalleh\FilamentShield\Support\Utils;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

trait HasShieldRelationManagerAccess {
    /**
     * Override the can() method to check relation manager specific permissions
     * This is called by canCreate(), canEdit(), canDelete(), etc.
     */
    protected function can(string $action, ?\Illuminate\Database\Eloquent\Model $record = null): bool {
        // If relation managers are not enabled, use parent's authorization
        if (! config('filament-shield.relation_managers.enabled')) {
            return parent::can($action, $record);
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return false;
        }

        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return parent::can($action, $record);
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Generate the permission key
        $permissionName = Utils::generateRelationManagerPermissionKey(
            $action,
            $resourceSlug,
            $relationManagerClass,
        );

        // Check if user has the specific relation manager permission
        return $user->can($permissionName);
    }

    /**
     * Check if the user can view this relation manager.
     * If relation_managers are enabled, checks specific permission,
     * otherwise falls back to resource permission.
     */
    protected function canView(Model $record): bool {
        return $this->can('view', $record);
    }

    /**
     * Check if the user can create records in this relation manager.
     */
    protected function canCreate(): bool {
        return $this->can('create');
    }

    /**
     * Check if the user can update records in this relation manager.
     */
    protected function canEdit(Model $record): bool {
        return $this->can('update', $record);
    }

    /**
     * Check if the user can delete records in this relation manager.
     */
    protected function canDelete(Model $record): bool {
        return $this->can('delete', $record);
    }

    /**
     * Extract resource slug from the relation manager's namespace
     * Example: App\Filament\Admin\Resources\MemberResource\RelationManagers\HistoryRelationManager
     * Returns: member
     */
    protected function extractResourceSlugFromNamespace(): ?string {
        $namespace = static::class;

        // Extract the resource class name from namespace
        if (preg_match('/Resources\\\\(\w+Resource)\\\\RelationManagers/', $namespace, $matches)) {
            $resourceClass = $matches[1];

            // Convert MemberResource -> member
            return Str::of($resourceClass)
                ->beforeLast('Resource')
                ->kebab()
                ->toString();
        }

        return null;
    }

    /**
     * Check if the user can view this relation manager for a specific owner record
     * This is called by Filament to determine if the relation manager tab should be visible
     */
    public static function canViewForRecord(Model $ownerRecord, string $pageClass): bool {
        // Get a temporary instance to extract the resource slug
        $tempInstance = new static();
        $resourceSlug = $tempInstance->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return parent::canViewForRecord($ownerRecord, $pageClass);
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return false;
        }

        // Check if relation managers are enabled
        if (! config('filament-shield.relation_managers.enabled')) {
            return parent::canViewForRecord($ownerRecord, $pageClass);
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Generate the permission key for 'view'
        $permissionName = Utils::generateRelationManagerPermissionKey(
            'view',
            $resourceSlug,
            $relationManagerClass,
        );

        // Check if user has the specific relation manager permission
        if ($user->can($permissionName)) {
            return true;
        }

        // Fall back to checking resource permission
        $resourcePermissionName = "view_{$resourceSlug}";
        return $user->can($resourcePermissionName);
    }

    /**
     * Check if the relation manager should be read-only
     * Returns false if the user has create/update/delete permissions, true otherwise
     */
    public function isReadOnly(): bool {
        // Check if relation managers are enabled
        if (! config('filament-shield.relation_managers.enabled')) {
            return parent::isReadOnly();
        }

        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return parent::isReadOnly();
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return true;
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Check if user has any write permissions (create, update, or delete)
        $canCreate = Utils::generateRelationManagerPermissionKey('create', $resourceSlug, $relationManagerClass);
        $canUpdate = Utils::generateRelationManagerPermissionKey('update', $resourceSlug, $relationManagerClass);
        $canDelete = Utils::generateRelationManagerPermissionKey('delete', $resourceSlug, $relationManagerClass);

        $hasWritePermission = $user->can($canCreate) || $user->can($canUpdate) || $user->can($canDelete);

        // If no relation-specific permissions, check resource-level permissions
        if (! $hasWritePermission) {
            $hasWritePermission = $user->can("create_{$resourceSlug}") ||
                $user->can("update_{$resourceSlug}") ||
                $user->can("delete_{$resourceSlug}");
        }

        return ! $hasWritePermission;
    }
}
