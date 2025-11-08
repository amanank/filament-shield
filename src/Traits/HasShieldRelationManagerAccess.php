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
        if ($user->can($permissionName)) {
            return true;
        }

        // Fall back to resource permission
        $resourcePermissionName = "{$action}_{$resourceSlug}";
        return $user->can($resourcePermissionName);
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
}
